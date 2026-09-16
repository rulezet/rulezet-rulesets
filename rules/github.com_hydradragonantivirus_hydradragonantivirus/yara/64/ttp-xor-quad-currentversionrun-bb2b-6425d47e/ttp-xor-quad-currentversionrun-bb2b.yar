rule TTP_XOR_QUAD_CurrentVersionRun_bb2b {
  strings:
    $key_bb2b = { e8 44 [2] cc 4a [2] e7 66 [2] c9 44 [2] dd 5f [2] d2 45 [2] cc 58 [2] ce 59 [2] d5 5f [2] c9 58 [2] d5 77 }

  condition:
    any of them
}