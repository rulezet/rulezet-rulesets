rule TTP_XOR_QUAD_CurrentVersionRun_27cd {
  strings:
    $key_27cd = { 74 a2 [2] 50 ac [2] 7b 80 [2] 55 a2 [2] 41 b9 [2] 4e a3 [2] 50 be [2] 52 bf [2] 49 b9 [2] 55 be [2] 49 91 }

  condition:
    any of them
}