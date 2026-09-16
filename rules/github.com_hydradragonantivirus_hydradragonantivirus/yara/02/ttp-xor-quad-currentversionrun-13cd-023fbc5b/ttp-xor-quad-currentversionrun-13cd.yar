rule TTP_XOR_QUAD_CurrentVersionRun_13cd {
  strings:
    $key_13cd = { 40 a2 [2] 64 ac [2] 4f 80 [2] 61 a2 [2] 75 b9 [2] 7a a3 [2] 64 be [2] 66 bf [2] 7d b9 [2] 61 be [2] 7d 91 }

  condition:
    any of them
}