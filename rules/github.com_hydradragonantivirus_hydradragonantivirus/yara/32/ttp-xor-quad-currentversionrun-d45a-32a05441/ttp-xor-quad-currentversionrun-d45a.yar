rule TTP_XOR_QUAD_CurrentVersionRun_d45a {
  strings:
    $key_d45a = { 87 35 [2] a3 3b [2] 88 17 [2] a6 35 [2] b2 2e [2] bd 34 [2] a3 29 [2] a1 28 [2] ba 2e [2] a6 29 [2] ba 06 }

  condition:
    any of them
}