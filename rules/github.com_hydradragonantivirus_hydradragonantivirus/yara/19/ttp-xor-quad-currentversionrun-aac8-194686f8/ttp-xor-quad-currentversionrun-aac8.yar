rule TTP_XOR_QUAD_CurrentVersionRun_aac8 {
  strings:
    $key_aac8 = { f9 a7 [2] dd a9 [2] f6 85 [2] d8 a7 [2] cc bc [2] c3 a6 [2] dd bb [2] df ba [2] c4 bc [2] d8 bb [2] c4 94 }

  condition:
    any of them
}