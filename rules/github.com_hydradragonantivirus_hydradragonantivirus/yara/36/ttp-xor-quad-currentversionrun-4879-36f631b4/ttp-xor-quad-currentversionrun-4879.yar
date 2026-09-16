rule TTP_XOR_QUAD_CurrentVersionRun_4879 {
  strings:
    $key_4879 = { 1b 16 [2] 3f 18 [2] 14 34 [2] 3a 16 [2] 2e 0d [2] 21 17 [2] 3f 0a [2] 3d 0b [2] 26 0d [2] 3a 0a [2] 26 25 }

  condition:
    any of them
}