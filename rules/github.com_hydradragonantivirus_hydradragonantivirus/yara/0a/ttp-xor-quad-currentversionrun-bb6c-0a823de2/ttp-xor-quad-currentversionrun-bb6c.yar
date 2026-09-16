rule TTP_XOR_QUAD_CurrentVersionRun_bb6c {
  strings:
    $key_bb6c = { e8 03 [2] cc 0d [2] e7 21 [2] c9 03 [2] dd 18 [2] d2 02 [2] cc 1f [2] ce 1e [2] d5 18 [2] c9 1f [2] d5 30 }

  condition:
    any of them
}