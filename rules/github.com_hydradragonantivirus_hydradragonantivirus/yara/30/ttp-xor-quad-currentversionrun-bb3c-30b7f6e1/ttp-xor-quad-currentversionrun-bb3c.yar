rule TTP_XOR_QUAD_CurrentVersionRun_bb3c {
  strings:
    $key_bb3c = { e8 53 [2] cc 5d [2] e7 71 [2] c9 53 [2] dd 48 [2] d2 52 [2] cc 4f [2] ce 4e [2] d5 48 [2] c9 4f [2] d5 60 }

  condition:
    any of them
}