rule TTP_XOR_QUAD_CurrentVersionRun_75cd {
  strings:
    $key_75cd = { 26 a2 [2] 02 ac [2] 29 80 [2] 07 a2 [2] 13 b9 [2] 1c a3 [2] 02 be [2] 00 bf [2] 1b b9 [2] 07 be [2] 1b 91 }

  condition:
    any of them
}