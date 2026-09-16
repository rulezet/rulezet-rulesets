rule TTP_XOR_QUAD_CurrentVersionRun_aa41 {
  strings:
    $key_aa41 = { f9 2e [2] dd 20 [2] f6 0c [2] d8 2e [2] cc 35 [2] c3 2f [2] dd 32 [2] df 33 [2] c4 35 [2] d8 32 [2] c4 1d }

  condition:
    any of them
}