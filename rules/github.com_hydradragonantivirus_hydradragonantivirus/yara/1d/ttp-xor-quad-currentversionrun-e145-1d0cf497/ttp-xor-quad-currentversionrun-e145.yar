rule TTP_XOR_QUAD_CurrentVersionRun_e145 {
  strings:
    $key_e145 = { b2 2a [2] 96 24 [2] bd 08 [2] 93 2a [2] 87 31 [2] 88 2b [2] 96 36 [2] 94 37 [2] 8f 31 [2] 93 36 [2] 8f 19 }

  condition:
    any of them
}