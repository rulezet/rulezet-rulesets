rule TTP_XOR_QUAD_CurrentVersionRun_8aae {
  strings:
    $key_8aae = { d9 c1 [2] fd cf [2] d6 e3 [2] f8 c1 [2] ec da [2] e3 c0 [2] fd dd [2] ff dc [2] e4 da [2] f8 dd [2] e4 f2 }

  condition:
    any of them
}