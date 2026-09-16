rule TTP_XOR_QUAD_CurrentVersionRun_88bc {
  strings:
    $key_88bc = { db d3 [2] ff dd [2] d4 f1 [2] fa d3 [2] ee c8 [2] e1 d2 [2] ff cf [2] fd ce [2] e6 c8 [2] fa cf [2] e6 e0 }

  condition:
    any of them
}