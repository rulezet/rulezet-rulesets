rule TTP_XOR_QUAD_CurrentVersionRun_88ae {
  strings:
    $key_88ae = { db c1 [2] ff cf [2] d4 e3 [2] fa c1 [2] ee da [2] e1 c0 [2] ff dd [2] fd dc [2] e6 da [2] fa dd [2] e6 f2 }

  condition:
    any of them
}