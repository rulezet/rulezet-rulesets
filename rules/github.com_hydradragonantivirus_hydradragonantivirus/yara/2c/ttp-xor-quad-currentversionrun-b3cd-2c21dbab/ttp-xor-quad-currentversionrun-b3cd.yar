rule TTP_XOR_QUAD_CurrentVersionRun_b3cd {
  strings:
    $key_b3cd = { e0 a2 [2] c4 ac [2] ef 80 [2] c1 a2 [2] d5 b9 [2] da a3 [2] c4 be [2] c6 bf [2] dd b9 [2] c1 be [2] dd 91 }

  condition:
    any of them
}