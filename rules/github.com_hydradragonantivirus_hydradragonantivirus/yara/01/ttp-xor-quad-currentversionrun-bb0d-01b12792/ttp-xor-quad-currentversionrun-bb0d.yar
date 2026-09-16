rule TTP_XOR_QUAD_CurrentVersionRun_bb0d {
  strings:
    $key_bb0d = { e8 62 [2] cc 6c [2] e7 40 [2] c9 62 [2] dd 79 [2] d2 63 [2] cc 7e [2] ce 7f [2] d5 79 [2] c9 7e [2] d5 51 }

  condition:
    any of them
}