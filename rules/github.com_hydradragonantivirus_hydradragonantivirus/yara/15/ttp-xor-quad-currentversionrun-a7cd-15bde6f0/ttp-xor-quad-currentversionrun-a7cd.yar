rule TTP_XOR_QUAD_CurrentVersionRun_a7cd {
  strings:
    $key_a7cd = { f4 a2 [2] d0 ac [2] fb 80 [2] d5 a2 [2] c1 b9 [2] ce a3 [2] d0 be [2] d2 bf [2] c9 b9 [2] d5 be [2] c9 91 }

  condition:
    any of them
}