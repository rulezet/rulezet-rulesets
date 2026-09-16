rule TTP_XOR_QUAD_CurrentVersionRun_e146 {
  strings:
    $key_e146 = { b2 29 [2] 96 27 [2] bd 0b [2] 93 29 [2] 87 32 [2] 88 28 [2] 96 35 [2] 94 34 [2] 8f 32 [2] 93 35 [2] 8f 1a }

  condition:
    any of them
}