rule TTP_XOR_QUAD_CurrentVersionRun_65cd {
  strings:
    $key_65cd = { 36 a2 [2] 12 ac [2] 39 80 [2] 17 a2 [2] 03 b9 [2] 0c a3 [2] 12 be [2] 10 bf [2] 0b b9 [2] 17 be [2] 0b 91 }

  condition:
    any of them
}