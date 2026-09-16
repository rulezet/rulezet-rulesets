rule TTP_XOR_QUAD_CurrentVersionRun_12cd {
  strings:
    $key_12cd = { 41 a2 [2] 65 ac [2] 4e 80 [2] 60 a2 [2] 74 b9 [2] 7b a3 [2] 65 be [2] 67 bf [2] 7c b9 [2] 60 be [2] 7c 91 }

  condition:
    any of them
}