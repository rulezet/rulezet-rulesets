rule TTP_XOR_QUAD_CurrentVersionRun_bb6d {
  strings:
    $key_bb6d = { e8 02 [2] cc 0c [2] e7 20 [2] c9 02 [2] dd 19 [2] d2 03 [2] cc 1e [2] ce 1f [2] d5 19 [2] c9 1e [2] d5 31 }

  condition:
    any of them
}