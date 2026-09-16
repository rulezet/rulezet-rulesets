rule TTP_XOR_QUAD_CurrentVersionRun_cff8 {
  strings:
    $key_cff8 = { 9c 97 [2] b8 99 [2] 93 b5 [2] bd 97 [2] a9 8c [2] a6 96 [2] b8 8b [2] ba 8a [2] a1 8c [2] bd 8b [2] a1 a4 }

  condition:
    any of them
}