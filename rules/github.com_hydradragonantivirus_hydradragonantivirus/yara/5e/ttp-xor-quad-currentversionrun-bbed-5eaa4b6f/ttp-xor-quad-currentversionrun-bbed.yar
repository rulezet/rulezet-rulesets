rule TTP_XOR_QUAD_CurrentVersionRun_bbed {
  strings:
    $key_bbed = { e8 82 [2] cc 8c [2] e7 a0 [2] c9 82 [2] dd 99 [2] d2 83 [2] cc 9e [2] ce 9f [2] d5 99 [2] c9 9e [2] d5 b1 }

  condition:
    any of them
}