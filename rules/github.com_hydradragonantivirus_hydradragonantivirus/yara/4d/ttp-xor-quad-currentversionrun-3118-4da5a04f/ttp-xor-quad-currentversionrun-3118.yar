rule TTP_XOR_QUAD_CurrentVersionRun_3118 {
  strings:
    $key_3118 = { 62 77 [2] 46 79 [2] 6d 55 [2] 43 77 [2] 57 6c [2] 58 76 [2] 46 6b [2] 44 6a [2] 5f 6c [2] 43 6b [2] 5f 44 }

  condition:
    any of them
}