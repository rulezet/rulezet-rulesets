rule TTP_XOR_QUAD_CurrentVersionRun_d352 {
  strings:
    $key_d352 = { 80 3d [2] a4 33 [2] 8f 1f [2] a1 3d [2] b5 26 [2] ba 3c [2] a4 21 [2] a6 20 [2] bd 26 [2] a1 21 [2] bd 0e }

  condition:
    any of them
}