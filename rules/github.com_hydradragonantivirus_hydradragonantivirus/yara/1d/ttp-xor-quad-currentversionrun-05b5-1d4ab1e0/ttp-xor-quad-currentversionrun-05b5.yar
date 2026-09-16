rule TTP_XOR_QUAD_CurrentVersionRun_05b5 {
  strings:
    $key_05b5 = { 56 da [2] 72 d4 [2] 59 f8 [2] 77 da [2] 63 c1 [2] 6c db [2] 72 c6 [2] 70 c7 [2] 6b c1 [2] 77 c6 [2] 6b e9 }

  condition:
    any of them
}