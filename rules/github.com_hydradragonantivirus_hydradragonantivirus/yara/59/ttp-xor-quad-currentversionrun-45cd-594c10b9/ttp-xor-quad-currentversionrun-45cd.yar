rule TTP_XOR_QUAD_CurrentVersionRun_45cd {
  strings:
    $key_45cd = { 16 a2 [2] 32 ac [2] 19 80 [2] 37 a2 [2] 23 b9 [2] 2c a3 [2] 32 be [2] 30 bf [2] 2b b9 [2] 37 be [2] 2b 91 }

  condition:
    any of them
}