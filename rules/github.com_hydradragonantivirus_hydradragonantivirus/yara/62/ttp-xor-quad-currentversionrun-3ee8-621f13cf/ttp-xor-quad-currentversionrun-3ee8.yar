rule TTP_XOR_QUAD_CurrentVersionRun_3ee8 {
  strings:
    $key_3ee8 = { 6d 87 [2] 49 89 [2] 62 a5 [2] 4c 87 [2] 58 9c [2] 57 86 [2] 49 9b [2] 4b 9a [2] 50 9c [2] 4c 9b [2] 50 b4 }

  condition:
    any of them
}