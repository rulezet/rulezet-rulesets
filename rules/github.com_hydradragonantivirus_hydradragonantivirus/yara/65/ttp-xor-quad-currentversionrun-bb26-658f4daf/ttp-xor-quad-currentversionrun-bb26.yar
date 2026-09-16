rule TTP_XOR_QUAD_CurrentVersionRun_bb26 {
  strings:
    $key_bb26 = { e8 49 [2] cc 47 [2] e7 6b [2] c9 49 [2] dd 52 [2] d2 48 [2] cc 55 [2] ce 54 [2] d5 52 [2] c9 55 [2] d5 7a }

  condition:
    any of them
}