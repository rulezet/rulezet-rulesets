rule TTP_XOR_QUAD_CurrentVersionRun_bb30 {
  strings:
    $key_bb30 = { e8 5f [2] cc 51 [2] e7 7d [2] c9 5f [2] dd 44 [2] d2 5e [2] cc 43 [2] ce 42 [2] d5 44 [2] c9 43 [2] d5 6c }

  condition:
    any of them
}