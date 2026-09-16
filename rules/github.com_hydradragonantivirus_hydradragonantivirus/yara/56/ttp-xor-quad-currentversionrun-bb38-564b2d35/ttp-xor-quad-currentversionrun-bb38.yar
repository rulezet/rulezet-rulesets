rule TTP_XOR_QUAD_CurrentVersionRun_bb38 {
  strings:
    $key_bb38 = { e8 57 [2] cc 59 [2] e7 75 [2] c9 57 [2] dd 4c [2] d2 56 [2] cc 4b [2] ce 4a [2] d5 4c [2] c9 4b [2] d5 64 }

  condition:
    any of them
}