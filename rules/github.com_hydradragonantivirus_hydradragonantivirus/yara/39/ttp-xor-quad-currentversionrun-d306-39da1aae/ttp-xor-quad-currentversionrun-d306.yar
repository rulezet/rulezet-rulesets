rule TTP_XOR_QUAD_CurrentVersionRun_d306 {
  strings:
    $key_d306 = { 80 69 [2] a4 67 [2] 8f 4b [2] a1 69 [2] b5 72 [2] ba 68 [2] a4 75 [2] a6 74 [2] bd 72 [2] a1 75 [2] bd 5a }

  condition:
    any of them
}