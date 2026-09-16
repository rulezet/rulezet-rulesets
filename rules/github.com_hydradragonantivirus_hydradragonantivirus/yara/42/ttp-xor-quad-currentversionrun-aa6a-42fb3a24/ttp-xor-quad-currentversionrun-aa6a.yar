rule TTP_XOR_QUAD_CurrentVersionRun_aa6a {
  strings:
    $key_aa6a = { f9 05 [2] dd 0b [2] f6 27 [2] d8 05 [2] cc 1e [2] c3 04 [2] dd 19 [2] df 18 [2] c4 1e [2] d8 19 [2] c4 36 }

  condition:
    any of them
}