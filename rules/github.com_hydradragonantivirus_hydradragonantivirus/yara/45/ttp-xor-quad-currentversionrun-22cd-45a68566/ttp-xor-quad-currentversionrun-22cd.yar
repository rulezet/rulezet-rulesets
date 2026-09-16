rule TTP_XOR_QUAD_CurrentVersionRun_22cd {
  strings:
    $key_22cd = { 71 a2 [2] 55 ac [2] 7e 80 [2] 50 a2 [2] 44 b9 [2] 4b a3 [2] 55 be [2] 57 bf [2] 4c b9 [2] 50 be [2] 4c 91 }

  condition:
    any of them
}