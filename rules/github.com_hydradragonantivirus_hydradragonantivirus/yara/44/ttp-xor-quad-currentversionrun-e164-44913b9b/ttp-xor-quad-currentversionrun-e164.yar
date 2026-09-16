rule TTP_XOR_QUAD_CurrentVersionRun_e164 {
  strings:
    $key_e164 = { b2 0b [2] 96 05 [2] bd 29 [2] 93 0b [2] 87 10 [2] 88 0a [2] 96 17 [2] 94 16 [2] 8f 10 [2] 93 17 [2] 8f 38 }

  condition:
    any of them
}