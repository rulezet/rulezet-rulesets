rule TTP_XOR_QUAD_CurrentVersionRun_bb2a {
  strings:
    $key_bb2a = { e8 45 [2] cc 4b [2] e7 67 [2] c9 45 [2] dd 5e [2] d2 44 [2] cc 59 [2] ce 58 [2] d5 5e [2] c9 59 [2] d5 76 }

  condition:
    any of them
}