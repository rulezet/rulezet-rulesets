rule TTP_XOR_QUAD_CurrentVersionRun_c1d0 {
  strings:
    $key_c1d0 = { 92 bf [2] b6 b1 [2] 9d 9d [2] b3 bf [2] a7 a4 [2] a8 be [2] b6 a3 [2] b4 a2 [2] af a4 [2] b3 a3 [2] af 8c }

  condition:
    any of them
}