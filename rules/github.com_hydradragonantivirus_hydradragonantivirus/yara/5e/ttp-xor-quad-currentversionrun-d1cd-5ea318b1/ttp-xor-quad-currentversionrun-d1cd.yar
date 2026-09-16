rule TTP_XOR_QUAD_CurrentVersionRun_d1cd {
  strings:
    $key_d1cd = { 82 a2 [2] a6 ac [2] 8d 80 [2] a3 a2 [2] b7 b9 [2] b8 a3 [2] a6 be [2] a4 bf [2] bf b9 [2] a3 be [2] bf 91 }

  condition:
    any of them
}