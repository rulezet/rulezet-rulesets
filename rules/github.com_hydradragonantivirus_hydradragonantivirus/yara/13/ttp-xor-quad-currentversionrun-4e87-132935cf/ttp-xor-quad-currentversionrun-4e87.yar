rule TTP_XOR_QUAD_CurrentVersionRun_4e87 {
  strings:
    $key_4e87 = { 1d e8 [2] 39 e6 [2] 12 ca [2] 3c e8 [2] 28 f3 [2] 27 e9 [2] 39 f4 [2] 3b f5 [2] 20 f3 [2] 3c f4 [2] 20 db }

  condition:
    any of them
}