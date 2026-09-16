rule TTP_XOR_QUAD_CurrentVersionRun_c2b2 {
  strings:
    $key_c2b2 = { 91 dd [2] b5 d3 [2] 9e ff [2] b0 dd [2] a4 c6 [2] ab dc [2] b5 c1 [2] b7 c0 [2] ac c6 [2] b0 c1 [2] ac ee }

  condition:
    any of them
}