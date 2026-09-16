rule TTP_XOR_QUAD_CurrentVersionRun_3eb5 {
  strings:
    $key_3eb5 = { 6d da [2] 49 d4 [2] 62 f8 [2] 4c da [2] 58 c1 [2] 57 db [2] 49 c6 [2] 4b c7 [2] 50 c1 [2] 4c c6 [2] 50 e9 }

  condition:
    any of them
}