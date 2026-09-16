rule TTP_XOR_QUAD_CurrentVersionRun_4819 {
  strings:
    $key_4819 = { 1b 76 [2] 3f 78 [2] 14 54 [2] 3a 76 [2] 2e 6d [2] 21 77 [2] 3f 6a [2] 3d 6b [2] 26 6d [2] 3a 6a [2] 26 45 }

  condition:
    any of them
}