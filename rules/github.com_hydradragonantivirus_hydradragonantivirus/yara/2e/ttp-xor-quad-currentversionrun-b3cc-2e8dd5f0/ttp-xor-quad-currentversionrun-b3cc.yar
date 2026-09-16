rule TTP_XOR_QUAD_CurrentVersionRun_b3cc {
  strings:
    $key_b3cc = { e0 a3 [2] c4 ad [2] ef 81 [2] c1 a3 [2] d5 b8 [2] da a2 [2] c4 bf [2] c6 be [2] dd b8 [2] c1 bf [2] dd 90 }

  condition:
    any of them
}