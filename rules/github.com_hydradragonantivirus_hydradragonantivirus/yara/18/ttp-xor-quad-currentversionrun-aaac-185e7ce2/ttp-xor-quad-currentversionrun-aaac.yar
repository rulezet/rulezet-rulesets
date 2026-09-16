rule TTP_XOR_QUAD_CurrentVersionRun_aaac {
  strings:
    $key_aaac = { f9 c3 [2] dd cd [2] f6 e1 [2] d8 c3 [2] cc d8 [2] c3 c2 [2] dd df [2] df de [2] c4 d8 [2] d8 df [2] c4 f0 }

  condition:
    any of them
}