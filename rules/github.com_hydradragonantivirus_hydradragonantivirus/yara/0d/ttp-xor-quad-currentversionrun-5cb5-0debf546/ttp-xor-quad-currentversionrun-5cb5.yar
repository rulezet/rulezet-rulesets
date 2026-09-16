rule TTP_XOR_QUAD_CurrentVersionRun_5cb5 {
  strings:
    $key_5cb5 = { 0f da [2] 2b d4 [2] 00 f8 [2] 2e da [2] 3a c1 [2] 35 db [2] 2b c6 [2] 29 c7 [2] 32 c1 [2] 2e c6 [2] 32 e9 }

  condition:
    any of them
}