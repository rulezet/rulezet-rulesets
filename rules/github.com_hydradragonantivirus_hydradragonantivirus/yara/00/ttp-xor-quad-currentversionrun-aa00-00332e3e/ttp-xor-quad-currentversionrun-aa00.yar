rule TTP_XOR_QUAD_CurrentVersionRun_aa00 {
  strings:
    $key_aa00 = { f9 6f [2] dd 61 [2] f6 4d [2] d8 6f [2] cc 74 [2] c3 6e [2] dd 73 [2] df 72 [2] c4 74 [2] d8 73 [2] c4 5c }

  condition:
    any of them
}