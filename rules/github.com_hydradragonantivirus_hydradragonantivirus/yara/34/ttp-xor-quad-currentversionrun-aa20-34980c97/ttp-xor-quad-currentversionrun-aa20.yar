rule TTP_XOR_QUAD_CurrentVersionRun_aa20 {
  strings:
    $key_aa20 = { f9 4f [2] dd 41 [2] f6 6d [2] d8 4f [2] cc 54 [2] c3 4e [2] dd 53 [2] df 52 [2] c4 54 [2] d8 53 [2] c4 7c }

  condition:
    any of them
}