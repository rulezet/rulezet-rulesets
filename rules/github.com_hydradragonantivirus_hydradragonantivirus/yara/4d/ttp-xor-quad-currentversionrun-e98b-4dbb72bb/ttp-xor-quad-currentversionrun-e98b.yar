rule TTP_XOR_QUAD_CurrentVersionRun_e98b {
  strings:
    $key_e98b = { ba e4 [2] 9e ea [2] b5 c6 [2] 9b e4 [2] 8f ff [2] 80 e5 [2] 9e f8 [2] 9c f9 [2] 87 ff [2] 9b f8 [2] 87 d7 }

  condition:
    any of them
}