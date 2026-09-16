rule TTP_XOR_QUAD_CurrentVersionRun_c84c {
  strings:
    $key_c84c = { 9b 23 [2] bf 2d [2] 94 01 [2] ba 23 [2] ae 38 [2] a1 22 [2] bf 3f [2] bd 3e [2] a6 38 [2] ba 3f [2] a6 10 }

  condition:
    any of them
}