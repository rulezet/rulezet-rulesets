rule TTP_XOR_QUAD_CurrentVersionRun_01ca {
  strings:
    $key_01ca = { 52 a5 [2] 76 ab [2] 5d 87 [2] 73 a5 [2] 67 be [2] 68 a4 [2] 76 b9 [2] 74 b8 [2] 6f be [2] 73 b9 [2] 6f 96 }

  condition:
    any of them
}