rule TTP_XOR_QUAD_CurrentVersionRun_ca33 {
  strings:
    $key_ca33 = { 99 5c [2] bd 52 [2] 96 7e [2] b8 5c [2] ac 47 [2] a3 5d [2] bd 40 [2] bf 41 [2] a4 47 [2] b8 40 [2] a4 6f }

  condition:
    any of them
}