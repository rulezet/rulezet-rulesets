rule TTP_XOR_QUAD_CurrentVersionRun_aa4a {
  strings:
    $key_aa4a = { f9 25 [2] dd 2b [2] f6 07 [2] d8 25 [2] cc 3e [2] c3 24 [2] dd 39 [2] df 38 [2] c4 3e [2] d8 39 [2] c4 16 }

  condition:
    any of them
}