rule TTP_XOR_QUAD_CurrentVersionRun_af93 {
  strings:
    $key_af93 = { fc fc [2] d8 f2 [2] f3 de [2] dd fc [2] c9 e7 [2] c6 fd [2] d8 e0 [2] da e1 [2] c1 e7 [2] dd e0 [2] c1 cf }

  condition:
    any of them
}