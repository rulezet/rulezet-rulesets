rule TTP_XOR_QUAD_CurrentVersionRun_88b2 {
  strings:
    $key_88b2 = { db dd [2] ff d3 [2] d4 ff [2] fa dd [2] ee c6 [2] e1 dc [2] ff c1 [2] fd c0 [2] e6 c6 [2] fa c1 [2] e6 ee }

  condition:
    any of them
}