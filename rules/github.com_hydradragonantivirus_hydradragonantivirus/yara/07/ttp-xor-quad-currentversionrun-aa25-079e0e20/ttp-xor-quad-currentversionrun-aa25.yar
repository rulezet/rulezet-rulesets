rule TTP_XOR_QUAD_CurrentVersionRun_aa25 {
  strings:
    $key_aa25 = { f9 4a [2] dd 44 [2] f6 68 [2] d8 4a [2] cc 51 [2] c3 4b [2] dd 56 [2] df 57 [2] c4 51 [2] d8 56 [2] c4 79 }

  condition:
    any of them
}