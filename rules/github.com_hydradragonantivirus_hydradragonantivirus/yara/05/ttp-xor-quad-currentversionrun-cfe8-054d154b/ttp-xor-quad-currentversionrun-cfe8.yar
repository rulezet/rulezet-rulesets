rule TTP_XOR_QUAD_CurrentVersionRun_cfe8 {
  strings:
    $key_cfe8 = { 9c 87 [2] b8 89 [2] 93 a5 [2] bd 87 [2] a9 9c [2] a6 86 [2] b8 9b [2] ba 9a [2] a1 9c [2] bd 9b [2] a1 b4 }

  condition:
    any of them
}