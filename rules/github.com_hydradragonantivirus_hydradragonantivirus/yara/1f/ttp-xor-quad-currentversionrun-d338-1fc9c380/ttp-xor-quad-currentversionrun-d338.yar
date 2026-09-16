rule TTP_XOR_QUAD_CurrentVersionRun_d338 {
  strings:
    $key_d338 = { 80 57 [2] a4 59 [2] 8f 75 [2] a1 57 [2] b5 4c [2] ba 56 [2] a4 4b [2] a6 4a [2] bd 4c [2] a1 4b [2] bd 64 }

  condition:
    any of them
}