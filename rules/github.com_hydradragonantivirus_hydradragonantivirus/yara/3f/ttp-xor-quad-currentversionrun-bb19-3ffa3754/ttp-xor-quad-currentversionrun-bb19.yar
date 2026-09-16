rule TTP_XOR_QUAD_CurrentVersionRun_bb19 {
  strings:
    $key_bb19 = { e8 76 [2] cc 78 [2] e7 54 [2] c9 76 [2] dd 6d [2] d2 77 [2] cc 6a [2] ce 6b [2] d5 6d [2] c9 6a [2] d5 45 }

  condition:
    any of them
}