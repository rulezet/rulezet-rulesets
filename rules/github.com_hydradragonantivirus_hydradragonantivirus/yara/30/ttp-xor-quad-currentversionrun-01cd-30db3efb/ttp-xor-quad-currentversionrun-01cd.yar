rule TTP_XOR_QUAD_CurrentVersionRun_01cd {
  strings:
    $key_01cd = { 52 a2 [2] 76 ac [2] 5d 80 [2] 73 a2 [2] 67 b9 [2] 68 a3 [2] 76 be [2] 74 bf [2] 6f b9 [2] 73 be [2] 6f 91 }

  condition:
    any of them
}