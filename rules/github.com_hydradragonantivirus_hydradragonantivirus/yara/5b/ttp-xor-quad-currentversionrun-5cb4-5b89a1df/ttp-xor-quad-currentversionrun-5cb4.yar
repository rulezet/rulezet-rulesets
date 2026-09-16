rule TTP_XOR_QUAD_CurrentVersionRun_5cb4 {
  strings:
    $key_5cb4 = { 0f db [2] 2b d5 [2] 00 f9 [2] 2e db [2] 3a c0 [2] 35 da [2] 2b c7 [2] 29 c6 [2] 32 c0 [2] 2e c7 [2] 32 e8 }

  condition:
    any of them
}