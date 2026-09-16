rule TTP_XOR_QUAD_CurrentVersionRun_b3c1 {
  strings:
    $key_b3c1 = { e0 ae [2] c4 a0 [2] ef 8c [2] c1 ae [2] d5 b5 [2] da af [2] c4 b2 [2] c6 b3 [2] dd b5 [2] c1 b2 [2] dd 9d }

  condition:
    any of them
}