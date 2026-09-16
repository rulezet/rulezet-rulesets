rule TTP_XOR_QUAD_CurrentVersionRun_bb20 {
  strings:
    $key_bb20 = { e8 4f [2] cc 41 [2] e7 6d [2] c9 4f [2] dd 54 [2] d2 4e [2] cc 53 [2] ce 52 [2] d5 54 [2] c9 53 [2] d5 7c }

  condition:
    any of them
}