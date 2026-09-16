rule TTP_XOR_QUAD_CurrentVersionRun_e663 {
  strings:
    $key_e663 = { b5 0c [2] 91 02 [2] ba 2e [2] 94 0c [2] 80 17 [2] 8f 0d [2] 91 10 [2] 93 11 [2] 88 17 [2] 94 10 [2] 88 3f }

  condition:
    any of them
}