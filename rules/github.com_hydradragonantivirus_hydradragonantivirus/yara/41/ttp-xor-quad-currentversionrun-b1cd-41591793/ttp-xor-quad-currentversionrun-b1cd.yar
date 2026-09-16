rule TTP_XOR_QUAD_CurrentVersionRun_b1cd {
  strings:
    $key_b1cd = { e2 a2 [2] c6 ac [2] ed 80 [2] c3 a2 [2] d7 b9 [2] d8 a3 [2] c6 be [2] c4 bf [2] df b9 [2] c3 be [2] df 91 }

  condition:
    any of them
}