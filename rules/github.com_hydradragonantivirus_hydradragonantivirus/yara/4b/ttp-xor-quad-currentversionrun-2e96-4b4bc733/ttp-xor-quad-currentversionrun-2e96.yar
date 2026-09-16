rule TTP_XOR_QUAD_CurrentVersionRun_2e96 {
  strings:
    $key_2e96 = { 7d f9 [2] 59 f7 [2] 72 db [2] 5c f9 [2] 48 e2 [2] 47 f8 [2] 59 e5 [2] 5b e4 [2] 40 e2 [2] 5c e5 [2] 40 ca }

  condition:
    any of them
}