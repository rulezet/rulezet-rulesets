rule TTP_XOR_QUAD_CurrentVersionRun_d6d0 {
  strings:
    $key_d6d0 = { 85 bf [2] a1 b1 [2] 8a 9d [2] a4 bf [2] b0 a4 [2] bf be [2] a1 a3 [2] a3 a2 [2] b8 a4 [2] a4 a3 [2] b8 8c }

  condition:
    any of them
}