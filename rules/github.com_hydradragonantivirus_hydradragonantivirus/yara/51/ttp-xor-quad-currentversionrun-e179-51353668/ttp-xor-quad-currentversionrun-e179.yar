rule TTP_XOR_QUAD_CurrentVersionRun_e179 {
  strings:
    $key_e179 = { b2 16 [2] 96 18 [2] bd 34 [2] 93 16 [2] 87 0d [2] 88 17 [2] 96 0a [2] 94 0b [2] 8f 0d [2] 93 0a [2] 8f 25 }

  condition:
    any of them
}