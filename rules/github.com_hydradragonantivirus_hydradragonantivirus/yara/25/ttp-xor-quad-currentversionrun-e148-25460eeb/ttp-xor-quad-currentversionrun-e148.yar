rule TTP_XOR_QUAD_CurrentVersionRun_e148 {
  strings:
    $key_e148 = { b2 27 [2] 96 29 [2] bd 05 [2] 93 27 [2] 87 3c [2] 88 26 [2] 96 3b [2] 94 3a [2] 8f 3c [2] 93 3b [2] 8f 14 }

  condition:
    any of them
}