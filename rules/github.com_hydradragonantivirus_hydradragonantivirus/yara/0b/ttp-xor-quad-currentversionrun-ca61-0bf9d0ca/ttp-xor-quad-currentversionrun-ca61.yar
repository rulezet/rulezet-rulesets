rule TTP_XOR_QUAD_CurrentVersionRun_ca61 {
  strings:
    $key_ca61 = { 99 0e [2] bd 00 [2] 96 2c [2] b8 0e [2] ac 15 [2] a3 0f [2] bd 12 [2] bf 13 [2] a4 15 [2] b8 12 [2] a4 3d }

  condition:
    any of them
}