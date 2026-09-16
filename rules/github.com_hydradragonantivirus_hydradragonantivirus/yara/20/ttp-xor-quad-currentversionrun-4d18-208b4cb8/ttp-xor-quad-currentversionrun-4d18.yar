rule TTP_XOR_QUAD_CurrentVersionRun_4d18 {
  strings:
    $key_4d18 = { 1e 77 [2] 3a 79 [2] 11 55 [2] 3f 77 [2] 2b 6c [2] 24 76 [2] 3a 6b [2] 38 6a [2] 23 6c [2] 3f 6b [2] 23 44 }

  condition:
    any of them
}