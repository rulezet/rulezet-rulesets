rule TTP_XOR_QUAD_CurrentVersionRun_bb08 {
  strings:
    $key_bb08 = { e8 67 [2] cc 69 [2] e7 45 [2] c9 67 [2] dd 7c [2] d2 66 [2] cc 7b [2] ce 7a [2] d5 7c [2] c9 7b [2] d5 54 }

  condition:
    any of them
}