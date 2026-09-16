rule TTP_XOR_QUAD_CurrentVersionRun_b7cd {
  strings:
    $key_b7cd = { e4 a2 [2] c0 ac [2] eb 80 [2] c5 a2 [2] d1 b9 [2] de a3 [2] c0 be [2] c2 bf [2] d9 b9 [2] c5 be [2] d9 91 }

  condition:
    any of them
}