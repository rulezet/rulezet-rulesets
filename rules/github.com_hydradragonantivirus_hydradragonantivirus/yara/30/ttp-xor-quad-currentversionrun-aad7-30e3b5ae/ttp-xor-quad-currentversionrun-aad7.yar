rule TTP_XOR_QUAD_CurrentVersionRun_aad7 {
  strings:
    $key_aad7 = { f9 b8 [2] dd b6 [2] f6 9a [2] d8 b8 [2] cc a3 [2] c3 b9 [2] dd a4 [2] df a5 [2] c4 a3 [2] d8 a4 [2] c4 8b }

  condition:
    any of them
}