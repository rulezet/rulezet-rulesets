rule TTP_XOR_QUAD_CurrentVersionRun_01e8 {
  strings:
    $key_01e8 = { 52 87 [2] 76 89 [2] 5d a5 [2] 73 87 [2] 67 9c [2] 68 86 [2] 76 9b [2] 74 9a [2] 6f 9c [2] 73 9b [2] 6f b4 }

  condition:
    any of them
}