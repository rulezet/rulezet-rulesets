rule TTP_XOR_QUAD_CurrentVersionRun_afc4 {
  strings:
    $key_afc4 = { fc ab [2] d8 a5 [2] f3 89 [2] dd ab [2] c9 b0 [2] c6 aa [2] d8 b7 [2] da b6 [2] c1 b0 [2] dd b7 [2] c1 98 }

  condition:
    any of them
}