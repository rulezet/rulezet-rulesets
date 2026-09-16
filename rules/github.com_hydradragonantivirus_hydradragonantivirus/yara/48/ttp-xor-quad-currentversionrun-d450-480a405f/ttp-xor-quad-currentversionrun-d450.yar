rule TTP_XOR_QUAD_CurrentVersionRun_d450 {
  strings:
    $key_d450 = { 87 3f [2] a3 31 [2] 88 1d [2] a6 3f [2] b2 24 [2] bd 3e [2] a3 23 [2] a1 22 [2] ba 24 [2] a6 23 [2] ba 0c }

  condition:
    any of them
}