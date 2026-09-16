rule TTP_XOR_QUAD_CurrentVersionRun_d4f9 {
  strings:
    $key_d4f9 = { 87 96 [2] a3 98 [2] 88 b4 [2] a6 96 [2] b2 8d [2] bd 97 [2] a3 8a [2] a1 8b [2] ba 8d [2] a6 8a [2] ba a5 }

  condition:
    any of them
}