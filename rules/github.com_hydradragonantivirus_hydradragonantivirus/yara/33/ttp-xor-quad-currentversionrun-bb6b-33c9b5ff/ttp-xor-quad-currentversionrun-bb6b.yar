rule TTP_XOR_QUAD_CurrentVersionRun_bb6b {
  strings:
    $key_bb6b = { e8 04 [2] cc 0a [2] e7 26 [2] c9 04 [2] dd 1f [2] d2 05 [2] cc 18 [2] ce 19 [2] d5 1f [2] c9 18 [2] d5 37 }

  condition:
    any of them
}