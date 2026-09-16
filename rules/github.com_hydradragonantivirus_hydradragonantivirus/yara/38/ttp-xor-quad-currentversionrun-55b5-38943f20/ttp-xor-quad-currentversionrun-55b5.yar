rule TTP_XOR_QUAD_CurrentVersionRun_55b5 {
  strings:
    $key_55b5 = { 06 da [2] 22 d4 [2] 09 f8 [2] 27 da [2] 33 c1 [2] 3c db [2] 22 c6 [2] 20 c7 [2] 3b c1 [2] 27 c6 [2] 3b e9 }

  condition:
    any of them
}