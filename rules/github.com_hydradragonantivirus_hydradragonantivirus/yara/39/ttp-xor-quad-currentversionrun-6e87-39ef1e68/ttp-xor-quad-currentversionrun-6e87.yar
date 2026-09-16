rule TTP_XOR_QUAD_CurrentVersionRun_6e87 {
  strings:
    $key_6e87 = { 3d e8 [2] 19 e6 [2] 32 ca [2] 1c e8 [2] 08 f3 [2] 07 e9 [2] 19 f4 [2] 1b f5 [2] 00 f3 [2] 1c f4 [2] 00 db }

  condition:
    any of them
}