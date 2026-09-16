rule TTP_XOR_QUAD_CurrentVersionRun_88a9 {
  strings:
    $key_88a9 = { db c6 [2] ff c8 [2] d4 e4 [2] fa c6 [2] ee dd [2] e1 c7 [2] ff da [2] fd db [2] e6 dd [2] fa da [2] e6 f5 }

  condition:
    any of them
}