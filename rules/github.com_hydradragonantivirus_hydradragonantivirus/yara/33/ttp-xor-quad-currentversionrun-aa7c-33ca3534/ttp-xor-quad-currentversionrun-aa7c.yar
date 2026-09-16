rule TTP_XOR_QUAD_CurrentVersionRun_aa7c {
  strings:
    $key_aa7c = { f9 13 [2] dd 1d [2] f6 31 [2] d8 13 [2] cc 08 [2] c3 12 [2] dd 0f [2] df 0e [2] c4 08 [2] d8 0f [2] c4 20 }

  condition:
    any of them
}