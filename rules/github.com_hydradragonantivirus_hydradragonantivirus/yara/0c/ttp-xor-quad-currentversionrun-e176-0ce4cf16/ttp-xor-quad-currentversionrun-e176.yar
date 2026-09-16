rule TTP_XOR_QUAD_CurrentVersionRun_e176 {
  strings:
    $key_e176 = { b2 19 [2] 96 17 [2] bd 3b [2] 93 19 [2] 87 02 [2] 88 18 [2] 96 05 [2] 94 04 [2] 8f 02 [2] 93 05 [2] 8f 2a }

  condition:
    any of them
}