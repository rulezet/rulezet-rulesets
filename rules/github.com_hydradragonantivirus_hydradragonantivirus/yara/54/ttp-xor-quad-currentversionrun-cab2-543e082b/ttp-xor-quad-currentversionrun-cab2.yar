rule TTP_XOR_QUAD_CurrentVersionRun_cab2 {
  strings:
    $key_cab2 = { 99 dd [2] bd d3 [2] 96 ff [2] b8 dd [2] ac c6 [2] a3 dc [2] bd c1 [2] bf c0 [2] a4 c6 [2] b8 c1 [2] a4 ee }

  condition:
    any of them
}