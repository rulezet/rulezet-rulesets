rule TTP_XOR_QUAD_CurrentVersionRun_4f96 {
  strings:
    $key_4f96 = { 1c f9 [2] 38 f7 [2] 13 db [2] 3d f9 [2] 29 e2 [2] 26 f8 [2] 38 e5 [2] 3a e4 [2] 21 e2 [2] 3d e5 [2] 21 ca }

  condition:
    any of them
}