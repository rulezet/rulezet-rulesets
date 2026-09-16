rule TTP_XOR_QUAD_CurrentVersionRun_aa4f {
  strings:
    $key_aa4f = { f9 20 [2] dd 2e [2] f6 02 [2] d8 20 [2] cc 3b [2] c3 21 [2] dd 3c [2] df 3d [2] c4 3b [2] d8 3c [2] c4 13 }

  condition:
    any of them
}