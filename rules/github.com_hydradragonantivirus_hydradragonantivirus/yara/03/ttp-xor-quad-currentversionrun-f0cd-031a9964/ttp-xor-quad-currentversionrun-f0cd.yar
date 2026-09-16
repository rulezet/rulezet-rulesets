rule TTP_XOR_QUAD_CurrentVersionRun_f0cd {
  strings:
    $key_f0cd = { a3 a2 [2] 87 ac [2] ac 80 [2] 82 a2 [2] 96 b9 [2] 99 a3 [2] 87 be [2] 85 bf [2] 9e b9 [2] 82 be [2] 9e 91 }

  condition:
    any of them
}