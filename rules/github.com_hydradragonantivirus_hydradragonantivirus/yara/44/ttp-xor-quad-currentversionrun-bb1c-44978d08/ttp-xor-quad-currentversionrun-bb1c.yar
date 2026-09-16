rule TTP_XOR_QUAD_CurrentVersionRun_bb1c {
  strings:
    $key_bb1c = { e8 73 [2] cc 7d [2] e7 51 [2] c9 73 [2] dd 68 [2] d2 72 [2] cc 6f [2] ce 6e [2] d5 68 [2] c9 6f [2] d5 40 }

  condition:
    any of them
}