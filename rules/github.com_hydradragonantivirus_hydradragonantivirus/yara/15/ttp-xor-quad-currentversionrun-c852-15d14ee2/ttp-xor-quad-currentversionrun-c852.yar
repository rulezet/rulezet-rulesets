rule TTP_XOR_QUAD_CurrentVersionRun_c852 {
  strings:
    $key_c852 = { 9b 3d [2] bf 33 [2] 94 1f [2] ba 3d [2] ae 26 [2] a1 3c [2] bf 21 [2] bd 20 [2] a6 26 [2] ba 21 [2] a6 0e }

  condition:
    any of them
}