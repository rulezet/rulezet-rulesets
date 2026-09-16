rule TTP_XOR_QUAD_CurrentVersionRun_d32a {
  strings:
    $key_d32a = { 80 45 [2] a4 4b [2] 8f 67 [2] a1 45 [2] b5 5e [2] ba 44 [2] a4 59 [2] a6 58 [2] bd 5e [2] a1 59 [2] bd 76 }

  condition:
    any of them
}