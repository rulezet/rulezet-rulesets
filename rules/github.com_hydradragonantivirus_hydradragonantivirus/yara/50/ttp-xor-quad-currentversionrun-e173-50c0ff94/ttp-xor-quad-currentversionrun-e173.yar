rule TTP_XOR_QUAD_CurrentVersionRun_e173 {
  strings:
    $key_e173 = { b2 1c [2] 96 12 [2] bd 3e [2] 93 1c [2] 87 07 [2] 88 1d [2] 96 00 [2] 94 01 [2] 8f 07 [2] 93 00 [2] 8f 2f }

  condition:
    any of them
}