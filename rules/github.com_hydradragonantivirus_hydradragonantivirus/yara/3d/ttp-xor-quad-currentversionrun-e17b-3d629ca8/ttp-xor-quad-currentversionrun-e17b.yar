rule TTP_XOR_QUAD_CurrentVersionRun_e17b {
  strings:
    $key_e17b = { b2 14 [2] 96 1a [2] bd 36 [2] 93 14 [2] 87 0f [2] 88 15 [2] 96 08 [2] 94 09 [2] 8f 0f [2] 93 08 [2] 8f 27 }

  condition:
    any of them
}