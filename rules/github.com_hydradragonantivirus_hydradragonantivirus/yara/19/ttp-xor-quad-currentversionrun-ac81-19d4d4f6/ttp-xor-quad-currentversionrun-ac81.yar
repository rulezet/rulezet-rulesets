rule TTP_XOR_QUAD_CurrentVersionRun_ac81 {
  strings:
    $key_ac81 = { ff ee [2] db e0 [2] f0 cc [2] de ee [2] ca f5 [2] c5 ef [2] db f2 [2] d9 f3 [2] c2 f5 [2] de f2 [2] c2 dd }

  condition:
    any of them
}