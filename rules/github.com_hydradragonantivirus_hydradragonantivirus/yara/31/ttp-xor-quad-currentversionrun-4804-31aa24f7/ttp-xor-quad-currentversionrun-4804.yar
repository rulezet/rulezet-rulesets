rule TTP_XOR_QUAD_CurrentVersionRun_4804 {
  strings:
    $key_4804 = { 1b 6b [2] 3f 65 [2] 14 49 [2] 3a 6b [2] 2e 70 [2] 21 6a [2] 3f 77 [2] 3d 76 [2] 26 70 [2] 3a 77 [2] 26 58 }

  condition:
    any of them
}