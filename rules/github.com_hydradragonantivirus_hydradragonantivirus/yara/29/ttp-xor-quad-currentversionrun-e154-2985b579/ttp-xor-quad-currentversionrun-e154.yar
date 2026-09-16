rule TTP_XOR_QUAD_CurrentVersionRun_e154 {
  strings:
    $key_e154 = { b2 3b [2] 96 35 [2] bd 19 [2] 93 3b [2] 87 20 [2] 88 3a [2] 96 27 [2] 94 26 [2] 8f 20 [2] 93 27 [2] 8f 08 }

  condition:
    any of them
}