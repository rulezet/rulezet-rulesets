rule TTP_XOR_QUAD_CurrentVersionRun_e172 {
  strings:
    $key_e172 = { b2 1d [2] 96 13 [2] bd 3f [2] 93 1d [2] 87 06 [2] 88 1c [2] 96 01 [2] 94 00 [2] 8f 06 [2] 93 01 [2] 8f 2e }

  condition:
    any of them
}