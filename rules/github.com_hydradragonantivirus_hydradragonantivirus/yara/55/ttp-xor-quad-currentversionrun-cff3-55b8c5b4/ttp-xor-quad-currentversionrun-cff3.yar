rule TTP_XOR_QUAD_CurrentVersionRun_cff3 {
  strings:
    $key_cff3 = { 9c 9c [2] b8 92 [2] 93 be [2] bd 9c [2] a9 87 [2] a6 9d [2] b8 80 [2] ba 81 [2] a1 87 [2] bd 80 [2] a1 af }

  condition:
    any of them
}