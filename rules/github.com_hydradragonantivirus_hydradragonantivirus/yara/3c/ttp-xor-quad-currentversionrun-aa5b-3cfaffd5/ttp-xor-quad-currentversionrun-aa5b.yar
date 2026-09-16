rule TTP_XOR_QUAD_CurrentVersionRun_aa5b {
  strings:
    $key_aa5b = { f9 34 [2] dd 3a [2] f6 16 [2] d8 34 [2] cc 2f [2] c3 35 [2] dd 28 [2] df 29 [2] c4 2f [2] d8 28 [2] c4 07 }

  condition:
    any of them
}