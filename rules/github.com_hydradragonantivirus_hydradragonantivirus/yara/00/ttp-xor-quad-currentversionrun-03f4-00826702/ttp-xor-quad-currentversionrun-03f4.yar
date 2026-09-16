rule TTP_XOR_QUAD_CurrentVersionRun_03f4 {
  strings:
    $key_03f4 = { 50 9b [2] 74 95 [2] 5f b9 [2] 71 9b [2] 65 80 [2] 6a 9a [2] 74 87 [2] 76 86 [2] 6d 80 [2] 71 87 [2] 6d a8 }

  condition:
    any of them
}