rule TTP_XOR_QUAD_CurrentVersionRun_d37d {
  strings:
    $key_d37d = { 80 12 [2] a4 1c [2] 8f 30 [2] a1 12 [2] b5 09 [2] ba 13 [2] a4 0e [2] a6 0f [2] bd 09 [2] a1 0e [2] bd 21 }

  condition:
    any of them
}