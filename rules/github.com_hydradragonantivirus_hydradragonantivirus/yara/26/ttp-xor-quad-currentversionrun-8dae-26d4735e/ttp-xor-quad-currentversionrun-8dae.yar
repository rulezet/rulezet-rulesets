rule TTP_XOR_QUAD_CurrentVersionRun_8dae {
  strings:
    $key_8dae = { de c1 [2] fa cf [2] d1 e3 [2] ff c1 [2] eb da [2] e4 c0 [2] fa dd [2] f8 dc [2] e3 da [2] ff dd [2] e3 f2 }

  condition:
    any of them
}