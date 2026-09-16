rule TTP_XOR_QUAD_CurrentVersionRun_e127 {
  strings:
    $key_e127 = { b2 48 [2] 96 46 [2] bd 6a [2] 93 48 [2] 87 53 [2] 88 49 [2] 96 54 [2] 94 55 [2] 8f 53 [2] 93 54 [2] 8f 7b }

  condition:
    any of them
}