rule TTP_XOR_QUAD_CurrentVersionRun_d317 {
  strings:
    $key_d317 = { 80 78 [2] a4 76 [2] 8f 5a [2] a1 78 [2] b5 63 [2] ba 79 [2] a4 64 [2] a6 65 [2] bd 63 [2] a1 64 [2] bd 4b }

  condition:
    any of them
}