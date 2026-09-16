rule TTP_XOR_QUAD_CurrentVersionRun_bb3e {
  strings:
    $key_bb3e = { e8 51 [2] cc 5f [2] e7 73 [2] c9 51 [2] dd 4a [2] d2 50 [2] cc 4d [2] ce 4c [2] d5 4a [2] c9 4d [2] d5 62 }

  condition:
    any of them
}