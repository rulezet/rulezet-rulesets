rule TTP_XOR_QUAD_CurrentVersionRun_cfb2 {
  strings:
    $key_cfb2 = { 9c dd [2] b8 d3 [2] 93 ff [2] bd dd [2] a9 c6 [2] a6 dc [2] b8 c1 [2] ba c0 [2] a1 c6 [2] bd c1 [2] a1 ee }

  condition:
    any of them
}