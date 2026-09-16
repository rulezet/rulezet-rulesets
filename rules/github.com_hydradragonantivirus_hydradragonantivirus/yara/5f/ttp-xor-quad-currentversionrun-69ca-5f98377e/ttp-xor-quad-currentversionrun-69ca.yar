rule TTP_XOR_QUAD_CurrentVersionRun_69ca {
  strings:
    $key_69ca = { 3a a5 [2] 1e ab [2] 35 87 [2] 1b a5 [2] 0f be [2] 00 a4 [2] 1e b9 [2] 1c b8 [2] 07 be [2] 1b b9 [2] 07 96 }

  condition:
    any of them
}