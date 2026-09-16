rule TTP_XOR_QUAD_CurrentVersionRun_e125 {
  strings:
    $key_e125 = { b2 4a [2] 96 44 [2] bd 68 [2] 93 4a [2] 87 51 [2] 88 4b [2] 96 56 [2] 94 57 [2] 8f 51 [2] 93 56 [2] 8f 79 }

  condition:
    any of them
}