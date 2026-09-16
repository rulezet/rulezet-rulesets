rule TTP_XOR_QUAD_CurrentVersionRun_2118 {
  strings:
    $key_2118 = { 72 77 [2] 56 79 [2] 7d 55 [2] 53 77 [2] 47 6c [2] 48 76 [2] 56 6b [2] 54 6a [2] 4f 6c [2] 53 6b [2] 4f 44 }

  condition:
    any of them
}