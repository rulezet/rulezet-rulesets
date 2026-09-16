rule TTP_XOR_QUAD_CurrentVersionRun_ca23 {
  strings:
    $key_ca23 = { 99 4c [2] bd 42 [2] 96 6e [2] b8 4c [2] ac 57 [2] a3 4d [2] bd 50 [2] bf 51 [2] a4 57 [2] b8 50 [2] a4 7f }

  condition:
    any of them
}