rule TTP_XOR_QUAD_CurrentVersionRun_c0cd {
  strings:
    $key_c0cd = { 93 a2 [2] b7 ac [2] 9c 80 [2] b2 a2 [2] a6 b9 [2] a9 a3 [2] b7 be [2] b5 bf [2] ae b9 [2] b2 be [2] ae 91 }

  condition:
    any of them
}