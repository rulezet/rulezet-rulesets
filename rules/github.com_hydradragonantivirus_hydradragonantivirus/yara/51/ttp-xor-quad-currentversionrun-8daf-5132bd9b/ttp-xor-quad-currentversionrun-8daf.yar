rule TTP_XOR_QUAD_CurrentVersionRun_8daf {
  strings:
    $key_8daf = { de c0 [2] fa ce [2] d1 e2 [2] ff c0 [2] eb db [2] e4 c1 [2] fa dc [2] f8 dd [2] e3 db [2] ff dc [2] e3 f3 }

  condition:
    any of them
}