rule TTP_XOR_QUAD_CurrentVersionRun_d42c {
  strings:
    $key_d42c = { 87 43 [2] a3 4d [2] 88 61 [2] a6 43 [2] b2 58 [2] bd 42 [2] a3 5f [2] a1 5e [2] ba 58 [2] a6 5f [2] ba 70 }

  condition:
    any of them
}