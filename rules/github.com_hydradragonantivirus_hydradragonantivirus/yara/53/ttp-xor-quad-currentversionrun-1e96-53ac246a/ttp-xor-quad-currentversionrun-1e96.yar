rule TTP_XOR_QUAD_CurrentVersionRun_1e96 {
  strings:
    $key_1e96 = { 4d f9 [2] 69 f7 [2] 42 db [2] 6c f9 [2] 78 e2 [2] 77 f8 [2] 69 e5 [2] 6b e4 [2] 70 e2 [2] 6c e5 [2] 70 ca }

  condition:
    any of them
}