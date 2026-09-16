rule TTP_XOR_QUAD_CurrentVersionRun_54d1 {
  strings:
    $key_54d1 = { 07 be [2] 23 b0 [2] 08 9c [2] 26 be [2] 32 a5 [2] 3d bf [2] 23 a2 [2] 21 a3 [2] 3a a5 [2] 26 a2 [2] 3a 8d }

  condition:
    any of them
}