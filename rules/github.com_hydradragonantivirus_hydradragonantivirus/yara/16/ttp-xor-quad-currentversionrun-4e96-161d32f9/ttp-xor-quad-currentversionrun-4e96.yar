rule TTP_XOR_QUAD_CurrentVersionRun_4e96 {
  strings:
    $key_4e96 = { 1d f9 [2] 39 f7 [2] 12 db [2] 3c f9 [2] 28 e2 [2] 27 f8 [2] 39 e5 [2] 3b e4 [2] 20 e2 [2] 3c e5 [2] 20 ca }

  condition:
    any of them
}