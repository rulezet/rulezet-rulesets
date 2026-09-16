rule TTP_XOR_QUAD_CurrentVersionRun_59ec {
  strings:
    $key_59ec = { 0a 83 [2] 2e 8d [2] 05 a1 [2] 2b 83 [2] 3f 98 [2] 30 82 [2] 2e 9f [2] 2c 9e [2] 37 98 [2] 2b 9f [2] 37 b0 }

  condition:
    any of them
}