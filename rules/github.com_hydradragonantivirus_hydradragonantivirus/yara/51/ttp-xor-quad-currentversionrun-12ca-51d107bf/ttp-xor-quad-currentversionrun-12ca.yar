rule TTP_XOR_QUAD_CurrentVersionRun_12ca {
  strings:
    $key_12ca = { 41 a5 [2] 65 ab [2] 4e 87 [2] 60 a5 [2] 74 be [2] 7b a4 [2] 65 b9 [2] 67 b8 [2] 7c be [2] 60 b9 [2] 7c 96 }

  condition:
    any of them
}