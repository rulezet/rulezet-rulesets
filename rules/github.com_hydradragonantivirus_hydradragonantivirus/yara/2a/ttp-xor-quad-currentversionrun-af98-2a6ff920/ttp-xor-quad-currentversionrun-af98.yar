rule TTP_XOR_QUAD_CurrentVersionRun_af98 {
  strings:
    $key_af98 = { fc f7 [2] d8 f9 [2] f3 d5 [2] dd f7 [2] c9 ec [2] c6 f6 [2] d8 eb [2] da ea [2] c1 ec [2] dd eb [2] c1 c4 }

  condition:
    any of them
}