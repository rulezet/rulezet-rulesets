rule TTP_XOR_QUAD_CurrentVersionRun_af81 {
  strings:
    $key_af81 = { fc ee [2] d8 e0 [2] f3 cc [2] dd ee [2] c9 f5 [2] c6 ef [2] d8 f2 [2] da f3 [2] c1 f5 [2] dd f2 [2] c1 dd }

  condition:
    any of them
}