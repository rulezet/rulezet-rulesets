rule TTP_XOR_QUAD_CurrentVersionRun_f7cd {
  strings:
    $key_f7cd = { a4 a2 [2] 80 ac [2] ab 80 [2] 85 a2 [2] 91 b9 [2] 9e a3 [2] 80 be [2] 82 bf [2] 99 b9 [2] 85 be [2] 99 91 }

  condition:
    any of them
}