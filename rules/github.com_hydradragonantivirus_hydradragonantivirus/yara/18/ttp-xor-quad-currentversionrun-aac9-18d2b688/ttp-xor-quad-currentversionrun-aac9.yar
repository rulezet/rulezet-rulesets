rule TTP_XOR_QUAD_CurrentVersionRun_aac9 {
  strings:
    $key_aac9 = { f9 a6 [2] dd a8 [2] f6 84 [2] d8 a6 [2] cc bd [2] c3 a7 [2] dd ba [2] df bb [2] c4 bd [2] d8 ba [2] c4 95 }

  condition:
    any of them
}