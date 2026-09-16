rule TTP_XOR_QUAD_CurrentVersionRun_d41c {
  strings:
    $key_d41c = { 87 73 [2] a3 7d [2] 88 51 [2] a6 73 [2] b2 68 [2] bd 72 [2] a3 6f [2] a1 6e [2] ba 68 [2] a6 6f [2] ba 40 }

  condition:
    any of them
}