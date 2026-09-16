rule TTP_XOR_QUAD_CurrentVersionRun_aa1d {
  strings:
    $key_aa1d = { f9 72 [2] dd 7c [2] f6 50 [2] d8 72 [2] cc 69 [2] c3 73 [2] dd 6e [2] df 6f [2] c4 69 [2] d8 6e [2] c4 41 }

  condition:
    any of them
}