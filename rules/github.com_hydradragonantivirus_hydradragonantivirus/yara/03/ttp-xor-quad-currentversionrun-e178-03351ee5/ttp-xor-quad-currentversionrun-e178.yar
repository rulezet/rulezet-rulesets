rule TTP_XOR_QUAD_CurrentVersionRun_e178 {
  strings:
    $key_e178 = { b2 17 [2] 96 19 [2] bd 35 [2] 93 17 [2] 87 0c [2] 88 16 [2] 96 0b [2] 94 0a [2] 8f 0c [2] 93 0b [2] 8f 24 }

  condition:
    any of them
}