rule TTP_XOR_QUAD_CurrentVersionRun_97b2 {
  strings:
    $key_97b2 = { c4 dd [2] e0 d3 [2] cb ff [2] e5 dd [2] f1 c6 [2] fe dc [2] e0 c1 [2] e2 c0 [2] f9 c6 [2] e5 c1 [2] f9 ee }

  condition:
    any of them
}