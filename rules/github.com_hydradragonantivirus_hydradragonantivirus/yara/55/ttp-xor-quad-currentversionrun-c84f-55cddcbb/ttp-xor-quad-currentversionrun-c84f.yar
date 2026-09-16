rule TTP_XOR_QUAD_CurrentVersionRun_c84f {
  strings:
    $key_c84f = { 9b 20 [2] bf 2e [2] 94 02 [2] ba 20 [2] ae 3b [2] a1 21 [2] bf 3c [2] bd 3d [2] a6 3b [2] ba 3c [2] a6 13 }

  condition:
    any of them
}