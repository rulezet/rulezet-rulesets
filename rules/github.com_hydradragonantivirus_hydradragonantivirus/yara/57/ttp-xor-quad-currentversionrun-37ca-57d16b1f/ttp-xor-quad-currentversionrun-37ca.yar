rule TTP_XOR_QUAD_CurrentVersionRun_37ca {
  strings:
    $key_37ca = { 64 a5 [2] 40 ab [2] 6b 87 [2] 45 a5 [2] 51 be [2] 5e a4 [2] 40 b9 [2] 42 b8 [2] 59 be [2] 45 b9 [2] 59 96 }

  condition:
    any of them
}