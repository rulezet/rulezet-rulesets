rule TTP_XOR_QUAD_CurrentVersionRun_af84 {
  strings:
    $key_af84 = { fc eb [2] d8 e5 [2] f3 c9 [2] dd eb [2] c9 f0 [2] c6 ea [2] d8 f7 [2] da f6 [2] c1 f0 [2] dd f7 [2] c1 d8 }

  condition:
    any of them
}