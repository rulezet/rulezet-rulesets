rule TTP_XOR_QUAD_CurrentVersionRun_8db2 {
  strings:
    $key_8db2 = { de dd [2] fa d3 [2] d1 ff [2] ff dd [2] eb c6 [2] e4 dc [2] fa c1 [2] f8 c0 [2] e3 c6 [2] ff c1 [2] e3 ee }

  condition:
    any of them
}