rule TTP_XOR_QUAD_CurrentVersionRun_aa52 {
  strings:
    $key_aa52 = { f9 3d [2] dd 33 [2] f6 1f [2] d8 3d [2] cc 26 [2] c3 3c [2] dd 21 [2] df 20 [2] c4 26 [2] d8 21 [2] c4 0e }

  condition:
    any of them
}