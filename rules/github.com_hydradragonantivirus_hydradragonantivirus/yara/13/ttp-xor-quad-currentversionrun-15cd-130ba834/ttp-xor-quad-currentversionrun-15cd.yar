rule TTP_XOR_QUAD_CurrentVersionRun_15cd {
  strings:
    $key_15cd = { 46 a2 [2] 62 ac [2] 49 80 [2] 67 a2 [2] 73 b9 [2] 7c a3 [2] 62 be [2] 60 bf [2] 7b b9 [2] 67 be [2] 7b 91 }

  condition:
    any of them
}