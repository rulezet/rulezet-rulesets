rule TTP_XOR_QUAD_CurrentVersionRun_d4f8 {
  strings:
    $key_d4f8 = { 87 97 [2] a3 99 [2] 88 b5 [2] a6 97 [2] b2 8c [2] bd 96 [2] a3 8b [2] a1 8a [2] ba 8c [2] a6 8b [2] ba a4 }

  condition:
    any of them
}