rule TTP_XOR_QUAD_CurrentVersionRun_23f4 {
  strings:
    $key_23f4 = { 70 9b [2] 54 95 [2] 7f b9 [2] 51 9b [2] 45 80 [2] 4a 9a [2] 54 87 [2] 56 86 [2] 4d 80 [2] 51 87 [2] 4d a8 }

  condition:
    any of them
}