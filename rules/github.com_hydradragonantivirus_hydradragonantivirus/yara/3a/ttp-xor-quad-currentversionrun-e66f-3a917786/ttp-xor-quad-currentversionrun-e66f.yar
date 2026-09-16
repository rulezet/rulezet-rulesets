rule TTP_XOR_QUAD_CurrentVersionRun_e66f {
  strings:
    $key_e66f = { b5 00 [2] 91 0e [2] ba 22 [2] 94 00 [2] 80 1b [2] 8f 01 [2] 91 1c [2] 93 1d [2] 88 1b [2] 94 1c [2] 88 33 }

  condition:
    any of them
}