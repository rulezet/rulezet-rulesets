rule TTP_XOR_QUAD_CurrentVersionRun_d404 {
  strings:
    $key_d404 = { 87 6b [2] a3 65 [2] 88 49 [2] a6 6b [2] b2 70 [2] bd 6a [2] a3 77 [2] a1 76 [2] ba 70 [2] a6 77 [2] ba 58 }

  condition:
    any of them
}