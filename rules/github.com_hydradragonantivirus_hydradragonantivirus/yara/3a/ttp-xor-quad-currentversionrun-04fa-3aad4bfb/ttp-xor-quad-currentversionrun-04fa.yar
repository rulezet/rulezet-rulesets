rule TTP_XOR_QUAD_CurrentVersionRun_04fa {
  strings:
    $key_04fa = { 57 95 [2] 73 9b [2] 58 b7 [2] 76 95 [2] 62 8e [2] 6d 94 [2] 73 89 [2] 71 88 [2] 6a 8e [2] 76 89 [2] 6a a6 }

  condition:
    any of them
}