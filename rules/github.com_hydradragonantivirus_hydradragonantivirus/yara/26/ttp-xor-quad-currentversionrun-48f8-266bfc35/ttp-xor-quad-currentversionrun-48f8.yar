rule TTP_XOR_QUAD_CurrentVersionRun_48f8 {
  strings:
    $key_48f8 = { 1b 97 [2] 3f 99 [2] 14 b5 [2] 3a 97 [2] 2e 8c [2] 21 96 [2] 3f 8b [2] 3d 8a [2] 26 8c [2] 3a 8b [2] 26 a4 }

  condition:
    any of them
}