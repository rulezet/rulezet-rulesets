rule TTP_XOR_QUAD_CurrentVersionRun_4218 {
  strings:
    $key_4218 = { 11 77 [2] 35 79 [2] 1e 55 [2] 30 77 [2] 24 6c [2] 2b 76 [2] 35 6b [2] 37 6a [2] 2c 6c [2] 30 6b [2] 2c 44 }

  condition:
    any of them
}