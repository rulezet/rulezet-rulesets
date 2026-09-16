rule TTP_XOR_QUAD_CurrentVersionRun_03e8 {
  strings:
    $key_03e8 = { 50 87 [2] 74 89 [2] 5f a5 [2] 71 87 [2] 65 9c [2] 6a 86 [2] 74 9b [2] 76 9a [2] 6d 9c [2] 71 9b [2] 6d b4 }

  condition:
    any of them
}