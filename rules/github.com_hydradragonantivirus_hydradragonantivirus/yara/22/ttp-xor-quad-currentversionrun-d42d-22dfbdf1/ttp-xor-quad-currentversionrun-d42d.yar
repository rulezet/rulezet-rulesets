rule TTP_XOR_QUAD_CurrentVersionRun_d42d {
  strings:
    $key_d42d = { 87 42 [2] a3 4c [2] 88 60 [2] a6 42 [2] b2 59 [2] bd 43 [2] a3 5e [2] a1 5f [2] ba 59 [2] a6 5e [2] ba 71 }

  condition:
    any of them
}