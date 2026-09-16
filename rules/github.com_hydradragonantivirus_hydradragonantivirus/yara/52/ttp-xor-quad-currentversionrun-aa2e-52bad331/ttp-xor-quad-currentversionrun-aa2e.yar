rule TTP_XOR_QUAD_CurrentVersionRun_aa2e {
  strings:
    $key_aa2e = { f9 41 [2] dd 4f [2] f6 63 [2] d8 41 [2] cc 5a [2] c3 40 [2] dd 5d [2] df 5c [2] c4 5a [2] d8 5d [2] c4 72 }

  condition:
    any of them
}