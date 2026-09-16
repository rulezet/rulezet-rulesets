rule TTP_XOR_QUAD_CurrentVersionRun_bb40 {
  strings:
    $key_bb40 = { e8 2f [2] cc 21 [2] e7 0d [2] c9 2f [2] dd 34 [2] d2 2e [2] cc 33 [2] ce 32 [2] d5 34 [2] c9 33 [2] d5 1c }

  condition:
    any of them
}