rule TTP_XOR_QUAD_CurrentVersionRun_c8ec {
  strings:
    $key_c8ec = { 9b 83 [2] bf 8d [2] 94 a1 [2] ba 83 [2] ae 98 [2] a1 82 [2] bf 9f [2] bd 9e [2] a6 98 [2] ba 9f [2] a6 b0 }

  condition:
    any of them
}