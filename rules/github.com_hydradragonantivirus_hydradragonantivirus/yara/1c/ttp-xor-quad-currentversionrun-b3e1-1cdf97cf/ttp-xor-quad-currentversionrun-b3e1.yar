rule TTP_XOR_QUAD_CurrentVersionRun_b3e1 {
  strings:
    $key_b3e1 = { e0 8e [2] c4 80 [2] ef ac [2] c1 8e [2] d5 95 [2] da 8f [2] c4 92 [2] c6 93 [2] dd 95 [2] c1 92 [2] dd bd }

  condition:
    any of them
}