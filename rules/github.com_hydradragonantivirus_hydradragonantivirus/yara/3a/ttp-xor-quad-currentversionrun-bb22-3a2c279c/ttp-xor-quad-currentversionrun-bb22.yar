rule TTP_XOR_QUAD_CurrentVersionRun_bb22 {
  strings:
    $key_bb22 = { e8 4d [2] cc 43 [2] e7 6f [2] c9 4d [2] dd 56 [2] d2 4c [2] cc 51 [2] ce 50 [2] d5 56 [2] c9 51 [2] d5 7e }

  condition:
    any of them
}