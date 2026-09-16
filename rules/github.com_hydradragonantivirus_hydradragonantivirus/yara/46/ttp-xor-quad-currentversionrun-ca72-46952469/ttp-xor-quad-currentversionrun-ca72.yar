rule TTP_XOR_QUAD_CurrentVersionRun_ca72 {
  strings:
    $key_ca72 = { 99 1d [2] bd 13 [2] 96 3f [2] b8 1d [2] ac 06 [2] a3 1c [2] bd 01 [2] bf 00 [2] a4 06 [2] b8 01 [2] a4 2e }

  condition:
    any of them
}