rule TTP_XOR_QUAD_CurrentVersionRun_7018 {
  strings:
    $key_7018 = { 23 77 [2] 07 79 [2] 2c 55 [2] 02 77 [2] 16 6c [2] 19 76 [2] 07 6b [2] 05 6a [2] 1e 6c [2] 02 6b [2] 1e 44 }

  condition:
    any of them
}