rule TTP_XOR_QUAD_CurrentVersionRun_64cd {
  strings:
    $key_64cd = { 37 a2 [2] 13 ac [2] 38 80 [2] 16 a2 [2] 02 b9 [2] 0d a3 [2] 13 be [2] 11 bf [2] 0a b9 [2] 16 be [2] 0a 91 }

  condition:
    any of them
}