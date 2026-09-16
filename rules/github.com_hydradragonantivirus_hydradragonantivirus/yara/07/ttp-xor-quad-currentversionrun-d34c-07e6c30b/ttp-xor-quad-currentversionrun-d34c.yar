rule TTP_XOR_QUAD_CurrentVersionRun_d34c {
  strings:
    $key_d34c = { 80 23 [2] a4 2d [2] 8f 01 [2] a1 23 [2] b5 38 [2] ba 22 [2] a4 3f [2] a6 3e [2] bd 38 [2] a1 3f [2] bd 10 }

  condition:
    any of them
}