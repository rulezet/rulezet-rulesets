rule TTP_XOR_QUAD_CurrentVersionRun_1eb5 {
  strings:
    $key_1eb5 = { 4d da [2] 69 d4 [2] 42 f8 [2] 6c da [2] 78 c1 [2] 77 db [2] 69 c6 [2] 6b c7 [2] 70 c1 [2] 6c c6 [2] 70 e9 }

  condition:
    any of them
}