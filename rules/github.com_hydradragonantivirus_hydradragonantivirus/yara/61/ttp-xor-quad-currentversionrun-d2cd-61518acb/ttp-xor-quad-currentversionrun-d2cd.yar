rule TTP_XOR_QUAD_CurrentVersionRun_d2cd {
  strings:
    $key_d2cd = { 81 a2 [2] a5 ac [2] 8e 80 [2] a0 a2 [2] b4 b9 [2] bb a3 [2] a5 be [2] a7 bf [2] bc b9 [2] a0 be [2] bc 91 }

  condition:
    any of them
}