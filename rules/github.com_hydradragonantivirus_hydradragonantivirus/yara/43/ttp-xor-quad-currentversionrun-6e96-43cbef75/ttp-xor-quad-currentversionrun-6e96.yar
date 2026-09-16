rule TTP_XOR_QUAD_CurrentVersionRun_6e96 {
  strings:
    $key_6e96 = { 3d f9 [2] 19 f7 [2] 32 db [2] 1c f9 [2] 08 e2 [2] 07 f8 [2] 19 e5 [2] 1b e4 [2] 00 e2 [2] 1c e5 [2] 00 ca }

  condition:
    any of them
}