rule TTP_XOR_QUAD_CurrentVersionRun_1b96 {
  strings:
    $key_1b96 = { 48 f9 [2] 6c f7 [2] 47 db [2] 69 f9 [2] 7d e2 [2] 72 f8 [2] 6c e5 [2] 6e e4 [2] 75 e2 [2] 69 e5 [2] 75 ca }

  condition:
    any of them
}