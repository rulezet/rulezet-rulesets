rule TTP_XOR_QUAD_CurrentVersionRun_c8fc {
  strings:
    $key_c8fc = { 9b 93 [2] bf 9d [2] 94 b1 [2] ba 93 [2] ae 88 [2] a1 92 [2] bf 8f [2] bd 8e [2] a6 88 [2] ba 8f [2] a6 a0 }

  condition:
    any of them
}