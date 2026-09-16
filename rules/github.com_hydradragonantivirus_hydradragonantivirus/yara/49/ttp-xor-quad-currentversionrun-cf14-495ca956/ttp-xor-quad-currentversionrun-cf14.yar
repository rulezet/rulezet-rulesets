rule TTP_XOR_QUAD_CurrentVersionRun_cf14 {
  strings:
    $key_cf14 = { 9c 7b [2] b8 75 [2] 93 59 [2] bd 7b [2] a9 60 [2] a6 7a [2] b8 67 [2] ba 66 [2] a1 60 [2] bd 67 [2] a1 48 }

  condition:
    any of them
}