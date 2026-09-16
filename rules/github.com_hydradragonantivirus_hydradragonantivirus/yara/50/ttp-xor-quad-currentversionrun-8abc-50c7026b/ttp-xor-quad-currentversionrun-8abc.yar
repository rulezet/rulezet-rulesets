rule TTP_XOR_QUAD_CurrentVersionRun_8abc {
  strings:
    $key_8abc = { d9 d3 [2] fd dd [2] d6 f1 [2] f8 d3 [2] ec c8 [2] e3 d2 [2] fd cf [2] ff ce [2] e4 c8 [2] f8 cf [2] e4 e0 }

  condition:
    any of them
}