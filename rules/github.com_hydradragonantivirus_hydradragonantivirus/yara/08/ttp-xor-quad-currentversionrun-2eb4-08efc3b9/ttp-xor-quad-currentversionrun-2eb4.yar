rule TTP_XOR_QUAD_CurrentVersionRun_2eb4 {
  strings:
    $key_2eb4 = { 7d db [2] 59 d5 [2] 72 f9 [2] 5c db [2] 48 c0 [2] 47 da [2] 59 c7 [2] 5b c6 [2] 40 c0 [2] 5c c7 [2] 40 e8 }

  condition:
    any of them
}