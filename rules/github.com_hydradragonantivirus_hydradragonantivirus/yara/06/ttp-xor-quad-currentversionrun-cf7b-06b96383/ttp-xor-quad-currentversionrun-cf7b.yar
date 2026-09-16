rule TTP_XOR_QUAD_CurrentVersionRun_cf7b {
  strings:
    $key_cf7b = { 9c 14 [2] b8 1a [2] 93 36 [2] bd 14 [2] a9 0f [2] a6 15 [2] b8 08 [2] ba 09 [2] a1 0f [2] bd 08 [2] a1 27 }

  condition:
    any of them
}