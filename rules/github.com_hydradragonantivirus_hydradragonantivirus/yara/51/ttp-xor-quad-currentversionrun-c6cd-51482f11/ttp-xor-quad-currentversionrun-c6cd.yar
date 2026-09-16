rule TTP_XOR_QUAD_CurrentVersionRun_c6cd {
  strings:
    $key_c6cd = { 95 a2 [2] b1 ac [2] 9a 80 [2] b4 a2 [2] a0 b9 [2] af a3 [2] b1 be [2] b3 bf [2] a8 b9 [2] b4 be [2] a8 91 }

  condition:
    any of them
}