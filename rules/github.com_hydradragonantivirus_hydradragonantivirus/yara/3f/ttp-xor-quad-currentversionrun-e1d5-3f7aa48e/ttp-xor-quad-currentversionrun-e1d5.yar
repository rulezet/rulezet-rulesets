rule TTP_XOR_QUAD_CurrentVersionRun_e1d5 {
  strings:
    $key_e1d5 = { b2 ba [2] 96 b4 [2] bd 98 [2] 93 ba [2] 87 a1 [2] 88 bb [2] 96 a6 [2] 94 a7 [2] 8f a1 [2] 93 a6 [2] 8f 89 }

  condition:
    any of them
}