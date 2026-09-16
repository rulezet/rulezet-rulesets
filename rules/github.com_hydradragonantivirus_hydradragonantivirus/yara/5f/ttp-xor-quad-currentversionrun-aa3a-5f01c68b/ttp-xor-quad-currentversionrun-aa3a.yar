rule TTP_XOR_QUAD_CurrentVersionRun_aa3a {
  strings:
    $key_aa3a = { f9 55 [2] dd 5b [2] f6 77 [2] d8 55 [2] cc 4e [2] c3 54 [2] dd 49 [2] df 48 [2] c4 4e [2] d8 49 [2] c4 66 }

  condition:
    any of them
}