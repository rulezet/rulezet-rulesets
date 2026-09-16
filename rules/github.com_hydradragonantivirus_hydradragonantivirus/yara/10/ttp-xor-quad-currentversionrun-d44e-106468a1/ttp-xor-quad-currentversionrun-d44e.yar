rule TTP_XOR_QUAD_CurrentVersionRun_d44e {
  strings:
    $key_d44e = { 87 21 [2] a3 2f [2] 88 03 [2] a6 21 [2] b2 3a [2] bd 20 [2] a3 3d [2] a1 3c [2] ba 3a [2] a6 3d [2] ba 12 }

  condition:
    any of them
}