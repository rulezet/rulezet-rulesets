rule TTP_XOR_QUAD_CurrentVersionRun_bb39 {
  strings:
    $key_bb39 = { e8 56 [2] cc 58 [2] e7 74 [2] c9 56 [2] dd 4d [2] d2 57 [2] cc 4a [2] ce 4b [2] d5 4d [2] c9 4a [2] d5 65 }

  condition:
    any of them
}