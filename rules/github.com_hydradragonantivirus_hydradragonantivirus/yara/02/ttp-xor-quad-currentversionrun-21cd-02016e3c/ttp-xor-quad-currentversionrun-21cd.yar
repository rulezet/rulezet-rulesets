rule TTP_XOR_QUAD_CurrentVersionRun_21cd {
  strings:
    $key_21cd = { 72 a2 [2] 56 ac [2] 7d 80 [2] 53 a2 [2] 47 b9 [2] 48 a3 [2] 56 be [2] 54 bf [2] 4f b9 [2] 53 be [2] 4f 91 }

  condition:
    any of them
}