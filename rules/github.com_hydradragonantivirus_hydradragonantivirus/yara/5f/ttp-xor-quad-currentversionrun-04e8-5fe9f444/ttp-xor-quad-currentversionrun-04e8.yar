rule TTP_XOR_QUAD_CurrentVersionRun_04e8 {
  strings:
    $key_04e8 = { 57 87 [2] 73 89 [2] 58 a5 [2] 76 87 [2] 62 9c [2] 6d 86 [2] 73 9b [2] 71 9a [2] 6a 9c [2] 76 9b [2] 6a b4 }

  condition:
    any of them
}