rule TTP_XOR_QUAD_CurrentVersionRun_bb76 {
  strings:
    $key_bb76 = { e8 19 [2] cc 17 [2] e7 3b [2] c9 19 [2] dd 02 [2] d2 18 [2] cc 05 [2] ce 04 [2] d5 02 [2] c9 05 [2] d5 2a }

  condition:
    any of them
}