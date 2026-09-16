rule TTP_XOR_QUAD_CurrentVersionRun_cfe5 {
  strings:
    $key_cfe5 = { 9c 8a [2] b8 84 [2] 93 a8 [2] bd 8a [2] a9 91 [2] a6 8b [2] b8 96 [2] ba 97 [2] a1 91 [2] bd 96 [2] a1 b9 }

  condition:
    any of them
}