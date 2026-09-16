rule TTP_XOR_QUAD_CurrentVersionRun_bb3d {
  strings:
    $key_bb3d = { e8 52 [2] cc 5c [2] e7 70 [2] c9 52 [2] dd 49 [2] d2 53 [2] cc 4e [2] ce 4f [2] d5 49 [2] c9 4e [2] d5 61 }

  condition:
    any of them
}