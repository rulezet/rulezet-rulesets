rule TTP_XOR_QUAD_CurrentVersionRun_47cd {
  strings:
    $key_47cd = { 14 a2 [2] 30 ac [2] 1b 80 [2] 35 a2 [2] 21 b9 [2] 2e a3 [2] 30 be [2] 32 bf [2] 29 b9 [2] 35 be [2] 29 91 }

  condition:
    any of them
}