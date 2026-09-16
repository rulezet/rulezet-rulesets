rule TTP_XOR_QUAD_CurrentVersionRun_2b96 {
  strings:
    $key_2b96 = { 78 f9 [2] 5c f7 [2] 77 db [2] 59 f9 [2] 4d e2 [2] 42 f8 [2] 5c e5 [2] 5e e4 [2] 45 e2 [2] 59 e5 [2] 45 ca }

  condition:
    any of them
}