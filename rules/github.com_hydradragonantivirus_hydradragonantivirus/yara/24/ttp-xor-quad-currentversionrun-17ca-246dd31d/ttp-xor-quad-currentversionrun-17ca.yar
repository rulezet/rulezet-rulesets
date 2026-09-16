rule TTP_XOR_QUAD_CurrentVersionRun_17ca {
  strings:
    $key_17ca = { 44 a5 [2] 60 ab [2] 4b 87 [2] 65 a5 [2] 71 be [2] 7e a4 [2] 60 b9 [2] 62 b8 [2] 79 be [2] 65 b9 [2] 79 96 }

  condition:
    any of them
}