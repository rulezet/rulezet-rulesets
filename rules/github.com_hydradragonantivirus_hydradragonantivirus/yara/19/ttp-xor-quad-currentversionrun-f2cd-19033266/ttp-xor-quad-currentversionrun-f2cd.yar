rule TTP_XOR_QUAD_CurrentVersionRun_f2cd {
  strings:
    $key_f2cd = { a1 a2 [2] 85 ac [2] ae 80 [2] 80 a2 [2] 94 b9 [2] 9b a3 [2] 85 be [2] 87 bf [2] 9c b9 [2] 80 be [2] 9c 91 }

  condition:
    any of them
}