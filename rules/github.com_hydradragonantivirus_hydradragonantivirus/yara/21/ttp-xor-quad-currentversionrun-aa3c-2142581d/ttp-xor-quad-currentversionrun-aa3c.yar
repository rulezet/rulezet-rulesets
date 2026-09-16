rule TTP_XOR_QUAD_CurrentVersionRun_aa3c {
  strings:
    $key_aa3c = { f9 53 [2] dd 5d [2] f6 71 [2] d8 53 [2] cc 48 [2] c3 52 [2] dd 4f [2] df 4e [2] c4 48 [2] d8 4f [2] c4 60 }

  condition:
    any of them
}