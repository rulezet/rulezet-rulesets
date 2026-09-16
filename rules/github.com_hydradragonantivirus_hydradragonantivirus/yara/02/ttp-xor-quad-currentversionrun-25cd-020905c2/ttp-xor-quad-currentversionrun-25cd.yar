rule TTP_XOR_QUAD_CurrentVersionRun_25cd {
  strings:
    $key_25cd = { 76 a2 [2] 52 ac [2] 79 80 [2] 57 a2 [2] 43 b9 [2] 4c a3 [2] 52 be [2] 50 bf [2] 4b b9 [2] 57 be [2] 4b 91 }

  condition:
    any of them
}