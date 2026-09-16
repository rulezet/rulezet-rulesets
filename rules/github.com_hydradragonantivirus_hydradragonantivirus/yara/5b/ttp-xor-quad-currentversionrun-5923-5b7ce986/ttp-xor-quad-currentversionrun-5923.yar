rule TTP_XOR_QUAD_CurrentVersionRun_5923 {
  strings:
    $key_5923 = { 0a 4c [2] 2e 42 [2] 05 6e [2] 2b 4c [2] 3f 57 [2] 30 4d [2] 2e 50 [2] 2c 51 [2] 37 57 [2] 2b 50 [2] 37 7f }

  condition:
    any of them
}