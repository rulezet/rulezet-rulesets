rule TTP_XOR_QUAD_CurrentVersionRun_62cd {
  strings:
    $key_62cd = { 31 a2 [2] 15 ac [2] 3e 80 [2] 10 a2 [2] 04 b9 [2] 0b a3 [2] 15 be [2] 17 bf [2] 0c b9 [2] 10 be [2] 0c 91 }

  condition:
    any of them
}