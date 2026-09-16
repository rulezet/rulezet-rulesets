rule TTP_XOR_QUAD_CurrentVersionRun_d46c {
  strings:
    $key_d46c = { 87 03 [2] a3 0d [2] 88 21 [2] a6 03 [2] b2 18 [2] bd 02 [2] a3 1f [2] a1 1e [2] ba 18 [2] a6 1f [2] ba 30 }

  condition:
    any of them
}