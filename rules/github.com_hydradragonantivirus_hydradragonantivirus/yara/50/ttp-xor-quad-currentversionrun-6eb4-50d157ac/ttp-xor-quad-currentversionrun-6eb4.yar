rule TTP_XOR_QUAD_CurrentVersionRun_6eb4 {
  strings:
    $key_6eb4 = { 3d db [2] 19 d5 [2] 32 f9 [2] 1c db [2] 08 c0 [2] 07 da [2] 19 c7 [2] 1b c6 [2] 00 c0 [2] 1c c7 [2] 00 e8 }

  condition:
    any of them
}