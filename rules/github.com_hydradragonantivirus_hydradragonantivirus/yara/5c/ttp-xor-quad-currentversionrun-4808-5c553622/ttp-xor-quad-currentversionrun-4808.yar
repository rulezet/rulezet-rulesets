rule TTP_XOR_QUAD_CurrentVersionRun_4808 {
  strings:
    $key_4808 = { 1b 67 [2] 3f 69 [2] 14 45 [2] 3a 67 [2] 2e 7c [2] 21 66 [2] 3f 7b [2] 3d 7a [2] 26 7c [2] 3a 7b [2] 26 54 }

  condition:
    any of them
}