rule TTP_XOR_QUAD_CurrentVersionRun_ca47 {
  strings:
    $key_ca47 = { 99 28 [2] bd 26 [2] 96 0a [2] b8 28 [2] ac 33 [2] a3 29 [2] bd 34 [2] bf 35 [2] a4 33 [2] b8 34 [2] a4 1b }

  condition:
    any of them
}