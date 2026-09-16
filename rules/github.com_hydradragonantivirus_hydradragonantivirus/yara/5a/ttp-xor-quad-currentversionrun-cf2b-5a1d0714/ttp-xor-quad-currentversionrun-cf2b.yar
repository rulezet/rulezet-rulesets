rule TTP_XOR_QUAD_CurrentVersionRun_cf2b {
  strings:
    $key_cf2b = { 9c 44 [2] b8 4a [2] 93 66 [2] bd 44 [2] a9 5f [2] a6 45 [2] b8 58 [2] ba 59 [2] a1 5f [2] bd 58 [2] a1 77 }

  condition:
    any of them
}