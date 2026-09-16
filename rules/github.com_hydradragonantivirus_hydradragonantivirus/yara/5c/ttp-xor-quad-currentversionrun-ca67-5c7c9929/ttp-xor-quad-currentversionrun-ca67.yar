rule TTP_XOR_QUAD_CurrentVersionRun_ca67 {
  strings:
    $key_ca67 = { 99 08 [2] bd 06 [2] 96 2a [2] b8 08 [2] ac 13 [2] a3 09 [2] bd 14 [2] bf 15 [2] a4 13 [2] b8 14 [2] a4 3b }

  condition:
    any of them
}