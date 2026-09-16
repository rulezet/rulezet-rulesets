rule TTP_XOR_QUAD_CurrentVersionRun_b3e0 {
  strings:
    $key_b3e0 = { e0 8f [2] c4 81 [2] ef ad [2] c1 8f [2] d5 94 [2] da 8e [2] c4 93 [2] c6 92 [2] dd 94 [2] c1 93 [2] dd bc }

  condition:
    any of them
}