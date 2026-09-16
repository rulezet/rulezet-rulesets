rule TTP_XOR_QUAD_CurrentVersionRun_e156 {
  strings:
    $key_e156 = { b2 39 [2] 96 37 [2] bd 1b [2] 93 39 [2] 87 22 [2] 88 38 [2] 96 25 [2] 94 24 [2] 8f 22 [2] 93 25 [2] 8f 0a }

  condition:
    any of them
}