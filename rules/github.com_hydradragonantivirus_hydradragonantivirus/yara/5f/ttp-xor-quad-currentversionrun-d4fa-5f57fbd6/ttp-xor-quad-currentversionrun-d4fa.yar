rule TTP_XOR_QUAD_CurrentVersionRun_d4fa {
  strings:
    $key_d4fa = { 87 95 [2] a3 9b [2] 88 b7 [2] a6 95 [2] b2 8e [2] bd 94 [2] a3 89 [2] a1 88 [2] ba 8e [2] a6 89 [2] ba a6 }

  condition:
    any of them
}