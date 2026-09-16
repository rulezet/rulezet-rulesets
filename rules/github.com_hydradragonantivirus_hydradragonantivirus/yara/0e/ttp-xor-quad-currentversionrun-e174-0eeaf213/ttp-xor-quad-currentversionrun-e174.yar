rule TTP_XOR_QUAD_CurrentVersionRun_e174 {
  strings:
    $key_e174 = { b2 1b [2] 96 15 [2] bd 39 [2] 93 1b [2] 87 00 [2] 88 1a [2] 96 07 [2] 94 06 [2] 8f 00 [2] 93 07 [2] 8f 28 }

  condition:
    any of them
}