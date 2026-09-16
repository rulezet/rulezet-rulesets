rule TTP_XOR_QUAD_CurrentVersionRun_e166 {
  strings:
    $key_e166 = { b2 09 [2] 96 07 [2] bd 2b [2] 93 09 [2] 87 12 [2] 88 08 [2] 96 15 [2] 94 14 [2] 8f 12 [2] 93 15 [2] 8f 3a }

  condition:
    any of them
}