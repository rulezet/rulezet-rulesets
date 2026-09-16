rule TTP_XOR_QUAD_CurrentVersionRun_afd2 {
  strings:
    $key_afd2 = { fc bd [2] d8 b3 [2] f3 9f [2] dd bd [2] c9 a6 [2] c6 bc [2] d8 a1 [2] da a0 [2] c1 a6 [2] dd a1 [2] c1 8e }

  condition:
    any of them
}