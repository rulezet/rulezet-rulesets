rule TTP_XOR_QUAD_CurrentVersionRun_e16f {
  strings:
    $key_e16f = { b2 00 [2] 96 0e [2] bd 22 [2] 93 00 [2] 87 1b [2] 88 01 [2] 96 1c [2] 94 1d [2] 8f 1b [2] 93 1c [2] 8f 33 }

  condition:
    any of them
}