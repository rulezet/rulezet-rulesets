rule TTP_XOR_QUAD_CurrentVersionRun_e1b2 {
  strings:
    $key_e1b2 = { b2 dd [2] 96 d3 [2] bd ff [2] 93 dd [2] 87 c6 [2] 88 dc [2] 96 c1 [2] 94 c0 [2] 8f c6 [2] 93 c1 [2] 8f ee }

  condition:
    any of them
}