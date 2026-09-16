rule TTP_XOR_QUAD_CurrentVersionRun_45ec {
  strings:
    $key_45ec = { 16 83 [2] 32 8d [2] 19 a1 [2] 37 83 [2] 23 98 [2] 2c 82 [2] 32 9f [2] 30 9e [2] 2b 98 [2] 37 9f [2] 2b b0 }

  condition:
    any of them
}