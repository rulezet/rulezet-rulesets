rule TTP_XOR_QUAD_CurrentVersionRun_a1cd {
  strings:
    $key_a1cd = { f2 a2 [2] d6 ac [2] fd 80 [2] d3 a2 [2] c7 b9 [2] c8 a3 [2] d6 be [2] d4 bf [2] cf b9 [2] d3 be [2] cf 91 }

  condition:
    any of them
}