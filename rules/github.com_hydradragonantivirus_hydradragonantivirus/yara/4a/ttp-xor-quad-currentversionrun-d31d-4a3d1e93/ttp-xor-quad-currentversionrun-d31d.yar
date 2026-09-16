rule TTP_XOR_QUAD_CurrentVersionRun_d31d {
  strings:
    $key_d31d = { 80 72 [2] a4 7c [2] 8f 50 [2] a1 72 [2] b5 69 [2] ba 73 [2] a4 6e [2] a6 6f [2] bd 69 [2] a1 6e [2] bd 41 }

  condition:
    any of them
}