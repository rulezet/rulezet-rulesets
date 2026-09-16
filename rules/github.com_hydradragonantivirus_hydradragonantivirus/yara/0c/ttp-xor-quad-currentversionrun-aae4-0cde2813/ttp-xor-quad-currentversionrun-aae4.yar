rule TTP_XOR_QUAD_CurrentVersionRun_aae4 {
  strings:
    $key_aae4 = { f9 8b [2] dd 85 [2] f6 a9 [2] d8 8b [2] cc 90 [2] c3 8a [2] dd 97 [2] df 96 [2] c4 90 [2] d8 97 [2] c4 b8 }

  condition:
    any of them
}