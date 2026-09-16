rule TTP_XOR_QUAD_CurrentVersionRun_ca60 {
  strings:
    $key_ca60 = { 99 0f [2] bd 01 [2] 96 2d [2] b8 0f [2] ac 14 [2] a3 0e [2] bd 13 [2] bf 12 [2] a4 14 [2] b8 13 [2] a4 3c }

  condition:
    any of them
}