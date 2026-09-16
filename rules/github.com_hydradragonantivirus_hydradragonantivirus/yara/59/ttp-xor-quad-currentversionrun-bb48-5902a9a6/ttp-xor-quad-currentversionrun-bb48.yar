rule TTP_XOR_QUAD_CurrentVersionRun_bb48 {
  strings:
    $key_bb48 = { e8 27 [2] cc 29 [2] e7 05 [2] c9 27 [2] dd 3c [2] d2 26 [2] cc 3b [2] ce 3a [2] d5 3c [2] c9 3b [2] d5 14 }

  condition:
    any of them
}