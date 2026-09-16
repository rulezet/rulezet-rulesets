rule TTP_XOR_QUAD_CurrentVersionRun_bb21 {
  strings:
    $key_bb21 = { e8 4e [2] cc 40 [2] e7 6c [2] c9 4e [2] dd 55 [2] d2 4f [2] cc 52 [2] ce 53 [2] d5 55 [2] c9 52 [2] d5 7d }

  condition:
    any of them
}