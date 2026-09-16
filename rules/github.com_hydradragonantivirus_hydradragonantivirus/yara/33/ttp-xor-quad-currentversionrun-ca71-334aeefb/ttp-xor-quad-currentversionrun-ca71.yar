rule TTP_XOR_QUAD_CurrentVersionRun_ca71 {
  strings:
    $key_ca71 = { 99 1e [2] bd 10 [2] 96 3c [2] b8 1e [2] ac 05 [2] a3 1f [2] bd 02 [2] bf 03 [2] a4 05 [2] b8 02 [2] a4 2d }

  condition:
    any of them
}