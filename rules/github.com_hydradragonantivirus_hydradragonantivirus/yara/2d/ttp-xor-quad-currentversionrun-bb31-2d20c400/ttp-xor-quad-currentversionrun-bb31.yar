rule TTP_XOR_QUAD_CurrentVersionRun_bb31 {
  strings:
    $key_bb31 = { e8 5e [2] cc 50 [2] e7 7c [2] c9 5e [2] dd 45 [2] d2 5f [2] cc 42 [2] ce 43 [2] d5 45 [2] c9 42 [2] d5 6d }

  condition:
    any of them
}