rule TTP_XOR_QUAD_CurrentVersionRun_d4d0 {
  strings:
    $key_d4d0 = { 87 bf [2] a3 b1 [2] 88 9d [2] a6 bf [2] b2 a4 [2] bd be [2] a3 a3 [2] a1 a2 [2] ba a4 [2] a6 a3 [2] ba 8c }

  condition:
    any of them
}