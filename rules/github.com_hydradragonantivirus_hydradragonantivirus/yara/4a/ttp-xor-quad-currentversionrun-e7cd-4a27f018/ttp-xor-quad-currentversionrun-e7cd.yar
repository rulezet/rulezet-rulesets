rule TTP_XOR_QUAD_CurrentVersionRun_e7cd {
  strings:
    $key_e7cd = { b4 a2 [2] 90 ac [2] bb 80 [2] 95 a2 [2] 81 b9 [2] 8e a3 [2] 90 be [2] 92 bf [2] 89 b9 [2] 95 be [2] 89 91 }

  condition:
    any of them
}