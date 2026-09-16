rule TTP_XOR_QUAD_CurrentVersionRun_cf1b {
  strings:
    $key_cf1b = { 9c 74 [2] b8 7a [2] 93 56 [2] bd 74 [2] a9 6f [2] a6 75 [2] b8 68 [2] ba 69 [2] a1 6f [2] bd 68 [2] a1 47 }

  condition:
    any of them
}