rule TTP_XOR_QUAD_CurrentVersionRun_e147 {
  strings:
    $key_e147 = { b2 28 [2] 96 26 [2] bd 0a [2] 93 28 [2] 87 33 [2] 88 29 [2] 96 34 [2] 94 35 [2] 8f 33 [2] 93 34 [2] 8f 1b }

  condition:
    any of them
}