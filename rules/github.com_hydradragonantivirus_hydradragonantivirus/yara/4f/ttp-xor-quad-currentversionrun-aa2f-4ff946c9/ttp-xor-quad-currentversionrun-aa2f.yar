rule TTP_XOR_QUAD_CurrentVersionRun_aa2f {
  strings:
    $key_aa2f = { f9 40 [2] dd 4e [2] f6 62 [2] d8 40 [2] cc 5b [2] c3 41 [2] dd 5c [2] df 5d [2] c4 5b [2] d8 5c [2] c4 73 }

  condition:
    any of them
}