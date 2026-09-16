rule TTP_XOR_QUAD_CurrentVersionRun_c4cd {
  strings:
    $key_c4cd = { 97 a2 [2] b3 ac [2] 98 80 [2] b6 a2 [2] a2 b9 [2] ad a3 [2] b3 be [2] b1 bf [2] aa b9 [2] b6 be [2] aa 91 }

  condition:
    any of them
}