rule TTP_XOR_QUAD_CurrentVersionRun_afa6 {
  strings:
    $key_afa6 = { fc c9 [2] d8 c7 [2] f3 eb [2] dd c9 [2] c9 d2 [2] c6 c8 [2] d8 d5 [2] da d4 [2] c1 d2 [2] dd d5 [2] c1 fa }

  condition:
    any of them
}