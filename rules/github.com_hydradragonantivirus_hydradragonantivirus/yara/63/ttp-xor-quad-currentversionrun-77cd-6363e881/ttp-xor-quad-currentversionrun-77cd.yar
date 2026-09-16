rule TTP_XOR_QUAD_CurrentVersionRun_77cd {
  strings:
    $key_77cd = { 24 a2 [2] 00 ac [2] 2b 80 [2] 05 a2 [2] 11 b9 [2] 1e a3 [2] 00 be [2] 02 bf [2] 19 b9 [2] 05 be [2] 19 91 }

  condition:
    any of them
}