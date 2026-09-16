rule TTP_XOR_QUAD_CurrentVersionRun_0eb4 {
  strings:
    $key_0eb4 = { 5d db [2] 79 d5 [2] 52 f9 [2] 7c db [2] 68 c0 [2] 67 da [2] 79 c7 [2] 7b c6 [2] 60 c0 [2] 7c c7 [2] 60 e8 }

  condition:
    any of them
}