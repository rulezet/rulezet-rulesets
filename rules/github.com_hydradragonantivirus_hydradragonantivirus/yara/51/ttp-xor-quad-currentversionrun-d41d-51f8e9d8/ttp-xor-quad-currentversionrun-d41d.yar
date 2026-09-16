rule TTP_XOR_QUAD_CurrentVersionRun_d41d {
  strings:
    $key_d41d = { 87 72 [2] a3 7c [2] 88 50 [2] a6 72 [2] b2 69 [2] bd 73 [2] a3 6e [2] a1 6f [2] ba 69 [2] a6 6e [2] ba 41 }

  condition:
    any of them
}