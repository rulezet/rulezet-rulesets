rule TTP_XOR_QUAD_CurrentVersionRun_aae6 {
  strings:
    $key_aae6 = { f9 89 [2] dd 87 [2] f6 ab [2] d8 89 [2] cc 92 [2] c3 88 [2] dd 95 [2] df 94 [2] c4 92 [2] d8 95 [2] c4 ba }

  condition:
    any of them
}