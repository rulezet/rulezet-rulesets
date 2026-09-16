rule TTP_XOR_QUAD_CurrentVersionRun_48e8 {
  strings:
    $key_48e8 = { 1b 87 [2] 3f 89 [2] 14 a5 [2] 3a 87 [2] 2e 9c [2] 21 86 [2] 3f 9b [2] 3d 9a [2] 26 9c [2] 3a 9b [2] 26 b4 }

  condition:
    any of them
}