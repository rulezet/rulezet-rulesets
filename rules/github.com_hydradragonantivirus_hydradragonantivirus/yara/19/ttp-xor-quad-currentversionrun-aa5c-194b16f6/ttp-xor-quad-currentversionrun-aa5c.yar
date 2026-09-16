rule TTP_XOR_QUAD_CurrentVersionRun_aa5c {
  strings:
    $key_aa5c = { f9 33 [2] dd 3d [2] f6 11 [2] d8 33 [2] cc 28 [2] c3 32 [2] dd 2f [2] df 2e [2] c4 28 [2] d8 2f [2] c4 00 }

  condition:
    any of them
}