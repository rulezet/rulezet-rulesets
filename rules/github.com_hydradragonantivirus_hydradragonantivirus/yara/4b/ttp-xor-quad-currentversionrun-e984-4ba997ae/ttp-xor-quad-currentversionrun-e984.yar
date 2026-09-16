rule TTP_XOR_QUAD_CurrentVersionRun_e984 {
  strings:
    $key_e984 = { ba eb [2] 9e e5 [2] b5 c9 [2] 9b eb [2] 8f f0 [2] 80 ea [2] 9e f7 [2] 9c f6 [2] 87 f0 [2] 9b f7 [2] 87 d8 }

  condition:
    any of them
}