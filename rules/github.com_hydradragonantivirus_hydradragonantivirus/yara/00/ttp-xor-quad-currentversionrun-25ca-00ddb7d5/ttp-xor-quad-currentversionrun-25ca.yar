rule TTP_XOR_QUAD_CurrentVersionRun_25ca {
  strings:
    $key_25ca = { 76 a5 [2] 52 ab [2] 79 87 [2] 57 a5 [2] 43 be [2] 4c a4 [2] 52 b9 [2] 50 b8 [2] 4b be [2] 57 b9 [2] 4b 96 }

  condition:
    any of them
}