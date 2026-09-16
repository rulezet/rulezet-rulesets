rule TTP_XOR_QUAD_CurrentVersionRun_cafc {
  strings:
    $key_cafc = { 99 93 [2] bd 9d [2] 96 b1 [2] b8 93 [2] ac 88 [2] a3 92 [2] bd 8f [2] bf 8e [2] a4 88 [2] b8 8f [2] a4 a0 }

  condition:
    any of them
}