rule TTP_XOR_QUAD_CurrentVersionRun_bb6a {
  strings:
    $key_bb6a = { e8 05 [2] cc 0b [2] e7 27 [2] c9 05 [2] dd 1e [2] d2 04 [2] cc 19 [2] ce 18 [2] d5 1e [2] c9 19 [2] d5 36 }

  condition:
    any of them
}