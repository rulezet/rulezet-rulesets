rule TTP_XOR_QUAD_CurrentVersionRun_bb51 {
  strings:
    $key_bb51 = { e8 3e [2] cc 30 [2] e7 1c [2] c9 3e [2] dd 25 [2] d2 3f [2] cc 22 [2] ce 23 [2] d5 25 [2] c9 22 [2] d5 0d }

  condition:
    any of them
}