rule TTP_XOR_QUAD_CurrentVersionRun_11cd {
  strings:
    $key_11cd = { 42 a2 [2] 66 ac [2] 4d 80 [2] 63 a2 [2] 77 b9 [2] 78 a3 [2] 66 be [2] 64 bf [2] 7f b9 [2] 63 be [2] 7f 91 }

  condition:
    any of them
}