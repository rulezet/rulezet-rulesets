rule TTP_XOR_QUAD_CurrentVersionRun_f6cd {
  strings:
    $key_f6cd = { a5 a2 [2] 81 ac [2] aa 80 [2] 84 a2 [2] 90 b9 [2] 9f a3 [2] 81 be [2] 83 bf [2] 98 b9 [2] 84 be [2] 98 91 }

  condition:
    any of them
}