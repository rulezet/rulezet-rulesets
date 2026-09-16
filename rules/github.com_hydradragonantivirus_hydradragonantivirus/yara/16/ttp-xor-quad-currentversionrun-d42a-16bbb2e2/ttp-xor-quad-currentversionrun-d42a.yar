rule TTP_XOR_QUAD_CurrentVersionRun_d42a {
  strings:
    $key_d42a = { 87 45 [2] a3 4b [2] 88 67 [2] a6 45 [2] b2 5e [2] bd 44 [2] a3 59 [2] a1 58 [2] ba 5e [2] a6 59 [2] ba 76 }

  condition:
    any of them
}