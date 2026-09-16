rule TTP_XOR_QUAD_CurrentVersionRun_d360 {
  strings:
    $key_d360 = { 80 0f [2] a4 01 [2] 8f 2d [2] a1 0f [2] b5 14 [2] ba 0e [2] a4 13 [2] a6 12 [2] bd 14 [2] a1 13 [2] bd 3c }

  condition:
    any of them
}