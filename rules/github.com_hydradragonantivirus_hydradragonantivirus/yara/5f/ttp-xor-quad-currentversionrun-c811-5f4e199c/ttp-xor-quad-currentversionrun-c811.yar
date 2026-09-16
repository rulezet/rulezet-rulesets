rule TTP_XOR_QUAD_CurrentVersionRun_c811 {
  strings:
    $key_c811 = { 9b 7e [2] bf 70 [2] 94 5c [2] ba 7e [2] ae 65 [2] a1 7f [2] bf 62 [2] bd 63 [2] a6 65 [2] ba 62 [2] a6 4d }

  condition:
    any of them
}