rule TTP_XOR_QUAD_CurrentVersionRun_53cd {
  strings:
    $key_53cd = { 00 a2 [2] 24 ac [2] 0f 80 [2] 21 a2 [2] 35 b9 [2] 3a a3 [2] 24 be [2] 26 bf [2] 3d b9 [2] 21 be [2] 3d 91 }

  condition:
    any of them
}