rule TTP_XOR_QUAD_CurrentVersionRun_c8b2 {
  strings:
    $key_c8b2 = { 9b dd [2] bf d3 [2] 94 ff [2] ba dd [2] ae c6 [2] a1 dc [2] bf c1 [2] bd c0 [2] a6 c6 [2] ba c1 [2] a6 ee }

  condition:
    any of them
}