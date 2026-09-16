rule TTP_XOR_QUAD_CurrentVersionRun_aaf8 {
  strings:
    $key_aaf8 = { f9 97 [2] dd 99 [2] f6 b5 [2] d8 97 [2] cc 8c [2] c3 96 [2] dd 8b [2] df 8a [2] c4 8c [2] d8 8b [2] c4 a4 }

  condition:
    any of them
}