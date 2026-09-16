rule TTP_XOR_QUAD_CurrentVersionRun_d47b {
  strings:
    $key_d47b = { 87 14 [2] a3 1a [2] 88 36 [2] a6 14 [2] b2 0f [2] bd 15 [2] a3 08 [2] a1 09 [2] ba 0f [2] a6 08 [2] ba 27 }

  condition:
    any of them
}