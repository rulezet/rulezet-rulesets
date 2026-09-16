rule TTP_XOR_QUAD_CurrentVersionRun_6b96 {
  strings:
    $key_6b96 = { 38 f9 [2] 1c f7 [2] 37 db [2] 19 f9 [2] 0d e2 [2] 02 f8 [2] 1c e5 [2] 1e e4 [2] 05 e2 [2] 19 e5 [2] 05 ca }

  condition:
    any of them
}