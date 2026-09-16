rule TTP_XOR_QUAD_CurrentVersionRun_74cd {
  strings:
    $key_74cd = { 27 a2 [2] 03 ac [2] 28 80 [2] 06 a2 [2] 12 b9 [2] 1d a3 [2] 03 be [2] 01 bf [2] 1a b9 [2] 06 be [2] 1a 91 }

  condition:
    any of them
}