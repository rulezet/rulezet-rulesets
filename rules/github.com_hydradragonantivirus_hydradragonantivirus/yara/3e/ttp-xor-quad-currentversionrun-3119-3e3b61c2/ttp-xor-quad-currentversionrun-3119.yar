rule TTP_XOR_QUAD_CurrentVersionRun_3119 {
  strings:
    $key_3119 = { 62 76 [2] 46 78 [2] 6d 54 [2] 43 76 [2] 57 6d [2] 58 77 [2] 46 6a [2] 44 6b [2] 5f 6d [2] 43 6a [2] 5f 45 }

  condition:
    any of them
}