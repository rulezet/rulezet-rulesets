rule TTP_XOR_QUAD_CurrentVersionRun_aaf5 {
  strings:
    $key_aaf5 = { f9 9a [2] dd 94 [2] f6 b8 [2] d8 9a [2] cc 81 [2] c3 9b [2] dd 86 [2] df 87 [2] c4 81 [2] d8 86 [2] c4 a9 }

  condition:
    any of them
}