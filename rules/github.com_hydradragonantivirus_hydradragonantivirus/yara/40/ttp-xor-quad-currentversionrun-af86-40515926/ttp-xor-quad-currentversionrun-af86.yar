rule TTP_XOR_QUAD_CurrentVersionRun_af86 {
  strings:
    $key_af86 = { fc e9 [2] d8 e7 [2] f3 cb [2] dd e9 [2] c9 f2 [2] c6 e8 [2] d8 f5 [2] da f4 [2] c1 f2 [2] dd f5 [2] c1 da }

  condition:
    any of them
}