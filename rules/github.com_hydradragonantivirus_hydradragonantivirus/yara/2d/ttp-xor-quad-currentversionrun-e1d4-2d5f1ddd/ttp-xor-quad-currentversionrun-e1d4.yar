rule TTP_XOR_QUAD_CurrentVersionRun_e1d4 {
  strings:
    $key_e1d4 = { b2 bb [2] 96 b5 [2] bd 99 [2] 93 bb [2] 87 a0 [2] 88 ba [2] 96 a7 [2] 94 a6 [2] 8f a0 [2] 93 a7 [2] 8f 88 }

  condition:
    any of them
}