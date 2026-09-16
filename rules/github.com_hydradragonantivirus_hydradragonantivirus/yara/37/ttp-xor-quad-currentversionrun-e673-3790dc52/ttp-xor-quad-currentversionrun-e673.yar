rule TTP_XOR_QUAD_CurrentVersionRun_e673 {
  strings:
    $key_e673 = { b5 1c [2] 91 12 [2] ba 3e [2] 94 1c [2] 80 07 [2] 8f 1d [2] 91 00 [2] 93 01 [2] 88 07 [2] 94 00 [2] 88 2f }

  condition:
    any of them
}