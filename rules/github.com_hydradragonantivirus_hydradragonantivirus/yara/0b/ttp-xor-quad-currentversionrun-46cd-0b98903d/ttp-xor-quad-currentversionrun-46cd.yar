rule TTP_XOR_QUAD_CurrentVersionRun_46cd {
  strings:
    $key_46cd = { 15 a2 [2] 31 ac [2] 1a 80 [2] 34 a2 [2] 20 b9 [2] 2f a3 [2] 31 be [2] 33 bf [2] 28 b9 [2] 34 be [2] 28 91 }

  condition:
    any of them
}