rule TTP_XOR_QUAD_CurrentVersionRun_aa3e {
  strings:
    $key_aa3e = { f9 51 [2] dd 5f [2] f6 73 [2] d8 51 [2] cc 4a [2] c3 50 [2] dd 4d [2] df 4c [2] c4 4a [2] d8 4d [2] c4 62 }

  condition:
    any of them
}