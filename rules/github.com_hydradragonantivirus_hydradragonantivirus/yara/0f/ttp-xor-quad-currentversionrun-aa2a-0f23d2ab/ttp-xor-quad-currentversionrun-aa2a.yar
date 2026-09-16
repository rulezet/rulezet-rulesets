rule TTP_XOR_QUAD_CurrentVersionRun_aa2a {
  strings:
    $key_aa2a = { f9 45 [2] dd 4b [2] f6 67 [2] d8 45 [2] cc 5e [2] c3 44 [2] dd 59 [2] df 58 [2] c4 5e [2] d8 59 [2] c4 76 }

  condition:
    any of them
}