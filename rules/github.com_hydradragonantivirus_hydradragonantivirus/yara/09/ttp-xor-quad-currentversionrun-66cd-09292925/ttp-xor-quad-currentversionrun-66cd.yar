rule TTP_XOR_QUAD_CurrentVersionRun_66cd {
  strings:
    $key_66cd = { 35 a2 [2] 11 ac [2] 3a 80 [2] 14 a2 [2] 00 b9 [2] 0f a3 [2] 11 be [2] 13 bf [2] 08 b9 [2] 14 be [2] 08 91 }

  condition:
    any of them
}