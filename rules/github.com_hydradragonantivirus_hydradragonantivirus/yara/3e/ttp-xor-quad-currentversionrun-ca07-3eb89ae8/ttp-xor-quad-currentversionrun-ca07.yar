rule TTP_XOR_QUAD_CurrentVersionRun_ca07 {
  strings:
    $key_ca07 = { 99 68 [2] bd 66 [2] 96 4a [2] b8 68 [2] ac 73 [2] a3 69 [2] bd 74 [2] bf 75 [2] a4 73 [2] b8 74 [2] a4 5b }

  condition:
    any of them
}