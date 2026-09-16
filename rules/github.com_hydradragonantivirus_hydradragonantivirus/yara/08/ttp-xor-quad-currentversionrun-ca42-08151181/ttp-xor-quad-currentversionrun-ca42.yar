rule TTP_XOR_QUAD_CurrentVersionRun_ca42 {
  strings:
    $key_ca42 = { 99 2d [2] bd 23 [2] 96 0f [2] b8 2d [2] ac 36 [2] a3 2c [2] bd 31 [2] bf 30 [2] a4 36 [2] b8 31 [2] a4 1e }

  condition:
    any of them
}