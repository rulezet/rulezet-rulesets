rule TTP_XOR_QUAD_CurrentVersionRun_d35a {
  strings:
    $key_d35a = { 80 35 [2] a4 3b [2] 8f 17 [2] a1 35 [2] b5 2e [2] ba 34 [2] a4 29 [2] a6 28 [2] bd 2e [2] a1 29 [2] bd 06 }

  condition:
    any of them
}