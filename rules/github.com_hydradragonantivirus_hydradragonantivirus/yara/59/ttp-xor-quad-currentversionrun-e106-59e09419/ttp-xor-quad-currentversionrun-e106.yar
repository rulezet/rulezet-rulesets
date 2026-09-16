rule TTP_XOR_QUAD_CurrentVersionRun_e106 {
  strings:
    $key_e106 = { b2 69 [2] 96 67 [2] bd 4b [2] 93 69 [2] 87 72 [2] 88 68 [2] 96 75 [2] 94 74 [2] 8f 72 [2] 93 75 [2] 8f 5a }

  condition:
    any of them
}