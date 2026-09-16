rule TTP_XOR_QUAD_CurrentVersionRun_e177 {
  strings:
    $key_e177 = { b2 18 [2] 96 16 [2] bd 3a [2] 93 18 [2] 87 03 [2] 88 19 [2] 96 04 [2] 94 05 [2] 8f 03 [2] 93 04 [2] 8f 2b }

  condition:
    any of them
}