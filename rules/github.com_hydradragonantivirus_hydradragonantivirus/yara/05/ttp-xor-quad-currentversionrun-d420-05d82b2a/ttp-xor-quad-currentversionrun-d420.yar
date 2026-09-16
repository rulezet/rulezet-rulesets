rule TTP_XOR_QUAD_CurrentVersionRun_d420 {
  strings:
    $key_d420 = { 87 4f [2] a3 41 [2] 88 6d [2] a6 4f [2] b2 54 [2] bd 4e [2] a3 53 [2] a1 52 [2] ba 54 [2] a6 53 [2] ba 7c }

  condition:
    any of them
}