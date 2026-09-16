rule TTP_XOR_QUAD_CurrentVersionRun_ca56 {
  strings:
    $key_ca56 = { 99 39 [2] bd 37 [2] 96 1b [2] b8 39 [2] ac 22 [2] a3 38 [2] bd 25 [2] bf 24 [2] a4 22 [2] b8 25 [2] a4 0a }

  condition:
    any of them
}