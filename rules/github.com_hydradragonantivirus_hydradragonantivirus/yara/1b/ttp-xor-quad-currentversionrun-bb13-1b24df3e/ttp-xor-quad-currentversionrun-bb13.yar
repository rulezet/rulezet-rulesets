rule TTP_XOR_QUAD_CurrentVersionRun_bb13 {
  strings:
    $key_bb13 = { e8 7c [2] cc 72 [2] e7 5e [2] c9 7c [2] dd 67 [2] d2 7d [2] cc 60 [2] ce 61 [2] d5 67 [2] c9 60 [2] d5 4f }

  condition:
    any of them
}