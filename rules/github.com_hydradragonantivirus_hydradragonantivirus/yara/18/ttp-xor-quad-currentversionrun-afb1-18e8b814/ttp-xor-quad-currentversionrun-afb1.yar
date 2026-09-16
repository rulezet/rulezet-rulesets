rule TTP_XOR_QUAD_CurrentVersionRun_afb1 {
  strings:
    $key_afb1 = { fc de [2] d8 d0 [2] f3 fc [2] dd de [2] c9 c5 [2] c6 df [2] d8 c2 [2] da c3 [2] c1 c5 [2] dd c2 [2] c1 ed }

  condition:
    any of them
}