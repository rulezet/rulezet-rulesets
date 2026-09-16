rule TTP_XOR_QUAD_CurrentVersionRun_aa38 {
  strings:
    $key_aa38 = { f9 57 [2] dd 59 [2] f6 75 [2] d8 57 [2] cc 4c [2] c3 56 [2] dd 4b [2] df 4a [2] c4 4c [2] d8 4b [2] c4 64 }

  condition:
    any of them
}