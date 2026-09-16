rule TTP_XOR_QUAD_CurrentVersionRun_dbb2 {
  strings:
    $key_dbb2 = { 88 dd [2] ac d3 [2] 87 ff [2] a9 dd [2] bd c6 [2] b2 dc [2] ac c1 [2] ae c0 [2] b5 c6 [2] a9 c1 [2] b5 ee }

  condition:
    any of them
}