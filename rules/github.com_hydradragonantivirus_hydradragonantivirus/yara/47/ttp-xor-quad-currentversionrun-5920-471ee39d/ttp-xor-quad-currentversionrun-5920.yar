rule TTP_XOR_QUAD_CurrentVersionRun_5920 {
  strings:
    $key_5920 = { 0a 4f [2] 2e 41 [2] 05 6d [2] 2b 4f [2] 3f 54 [2] 30 4e [2] 2e 53 [2] 2c 52 [2] 37 54 [2] 2b 53 [2] 37 7c }

  condition:
    any of them
}