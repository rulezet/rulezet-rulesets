rule TTP_XOR_QUAD_CurrentVersionRun_e116 {
  strings:
    $key_e116 = { b2 79 [2] 96 77 [2] bd 5b [2] 93 79 [2] 87 62 [2] 88 78 [2] 96 65 [2] 94 64 [2] 8f 62 [2] 93 65 [2] 8f 4a }

  condition:
    any of them
}