rule TTP_XOR_QUAD_CurrentVersionRun_ca63 {
  strings:
    $key_ca63 = { 99 0c [2] bd 02 [2] 96 2e [2] b8 0c [2] ac 17 [2] a3 0d [2] bd 10 [2] bf 11 [2] a4 17 [2] b8 10 [2] a4 3f }

  condition:
    any of them
}