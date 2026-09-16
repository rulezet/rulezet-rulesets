rule TTP_XOR_QUAD_CurrentVersionRun_c8d1 {
  strings:
    $key_c8d1 = { 9b be [2] bf b0 [2] 94 9c [2] ba be [2] ae a5 [2] a1 bf [2] bf a2 [2] bd a3 [2] a6 a5 [2] ba a2 [2] a6 8d }

  condition:
    any of them
}