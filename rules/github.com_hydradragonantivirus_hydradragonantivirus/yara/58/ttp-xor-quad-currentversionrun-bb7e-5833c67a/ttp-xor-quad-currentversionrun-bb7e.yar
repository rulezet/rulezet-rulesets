rule TTP_XOR_QUAD_CurrentVersionRun_bb7e {
  strings:
    $key_bb7e = { e8 11 [2] cc 1f [2] e7 33 [2] c9 11 [2] dd 0a [2] d2 10 [2] cc 0d [2] ce 0c [2] d5 0a [2] c9 0d [2] d5 22 }

  condition:
    any of them
}