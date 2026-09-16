rule TTP_XOR_QUAD_CurrentVersionRun_77ca {
  strings:
    $key_77ca = { 24 a5 [2] 00 ab [2] 2b 87 [2] 05 a5 [2] 11 be [2] 1e a4 [2] 00 b9 [2] 02 b8 [2] 19 be [2] 05 b9 [2] 19 96 }

  condition:
    any of them
}