rule TTP_XOR_QUAD_CurrentVersionRun_aa31 {
  strings:
    $key_aa31 = { f9 5e [2] dd 50 [2] f6 7c [2] d8 5e [2] cc 45 [2] c3 5f [2] dd 42 [2] df 43 [2] c4 45 [2] d8 42 [2] c4 6d }

  condition:
    any of them
}