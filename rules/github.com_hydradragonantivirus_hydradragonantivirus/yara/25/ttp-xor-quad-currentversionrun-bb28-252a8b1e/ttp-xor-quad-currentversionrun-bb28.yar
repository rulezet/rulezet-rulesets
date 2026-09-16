rule TTP_XOR_QUAD_CurrentVersionRun_bb28 {
  strings:
    $key_bb28 = { e8 47 [2] cc 49 [2] e7 65 [2] c9 47 [2] dd 5c [2] d2 46 [2] cc 5b [2] ce 5a [2] d5 5c [2] c9 5b [2] d5 74 }

  condition:
    any of them
}