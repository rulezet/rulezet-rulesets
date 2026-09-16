rule TTP_XOR_QUAD_CurrentVersionRun_bb7b {
  strings:
    $key_bb7b = { e8 14 [2] cc 1a [2] e7 36 [2] c9 14 [2] dd 0f [2] d2 15 [2] cc 08 [2] ce 09 [2] d5 0f [2] c9 08 [2] d5 27 }

  condition:
    any of them
}