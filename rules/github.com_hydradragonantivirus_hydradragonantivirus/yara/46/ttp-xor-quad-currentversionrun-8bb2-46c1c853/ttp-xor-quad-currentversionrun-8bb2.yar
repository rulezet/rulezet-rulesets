rule TTP_XOR_QUAD_CurrentVersionRun_8bb2 {
  strings:
    $key_8bb2 = { d8 dd [2] fc d3 [2] d7 ff [2] f9 dd [2] ed c6 [2] e2 dc [2] fc c1 [2] fe c0 [2] e5 c6 [2] f9 c1 [2] e5 ee }

  condition:
    any of them
}