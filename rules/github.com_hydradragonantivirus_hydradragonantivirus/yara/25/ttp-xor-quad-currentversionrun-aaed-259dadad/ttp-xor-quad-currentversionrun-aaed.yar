rule TTP_XOR_QUAD_CurrentVersionRun_aaed {
  strings:
    $key_aaed = { f9 82 [2] dd 8c [2] f6 a0 [2] d8 82 [2] cc 99 [2] c3 83 [2] dd 9e [2] df 9f [2] c4 99 [2] d8 9e [2] c4 b1 }

  condition:
    any of them
}