rule TTP_XOR_QUAD_CurrentVersionRun_c84e {
  strings:
    $key_c84e = { 9b 21 [2] bf 2f [2] 94 03 [2] ba 21 [2] ae 3a [2] a1 20 [2] bf 3d [2] bd 3c [2] a6 3a [2] ba 3d [2] a6 12 }

  condition:
    any of them
}