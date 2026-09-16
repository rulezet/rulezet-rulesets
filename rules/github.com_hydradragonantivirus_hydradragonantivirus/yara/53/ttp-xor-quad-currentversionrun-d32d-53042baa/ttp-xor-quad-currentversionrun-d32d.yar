rule TTP_XOR_QUAD_CurrentVersionRun_d32d {
  strings:
    $key_d32d = { 80 42 [2] a4 4c [2] 8f 60 [2] a1 42 [2] b5 59 [2] ba 43 [2] a4 5e [2] a6 5f [2] bd 59 [2] a1 5e [2] bd 71 }

  condition:
    any of them
}