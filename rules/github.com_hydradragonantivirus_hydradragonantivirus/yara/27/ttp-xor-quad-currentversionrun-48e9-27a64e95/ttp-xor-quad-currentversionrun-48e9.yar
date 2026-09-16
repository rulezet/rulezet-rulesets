rule TTP_XOR_QUAD_CurrentVersionRun_48e9 {
  strings:
    $key_48e9 = { 1b 86 [2] 3f 88 [2] 14 a4 [2] 3a 86 [2] 2e 9d [2] 21 87 [2] 3f 9a [2] 3d 9b [2] 26 9d [2] 3a 9a [2] 26 b5 }

  condition:
    any of them
}