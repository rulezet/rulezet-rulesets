rule TTP_XOR_QUAD_CurrentVersionRun_e6b2 {
  strings:
    $key_e6b2 = { b5 dd [2] 91 d3 [2] ba ff [2] 94 dd [2] 80 c6 [2] 8f dc [2] 91 c1 [2] 93 c0 [2] 88 c6 [2] 94 c1 [2] 88 ee }

  condition:
    any of them
}