rule TTP_XOR_QUAD_CurrentVersionRun_04da {
  strings:
    $key_04da = { 57 b5 [2] 73 bb [2] 58 97 [2] 76 b5 [2] 62 ae [2] 6d b4 [2] 73 a9 [2] 71 a8 [2] 6a ae [2] 76 a9 [2] 6a 86 }

  condition:
    any of them
}