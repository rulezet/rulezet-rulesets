rule TTP_XOR_QUAD_CurrentVersionRun_ca03 {
  strings:
    $key_ca03 = { 99 6c [2] bd 62 [2] 96 4e [2] b8 6c [2] ac 77 [2] a3 6d [2] bd 70 [2] bf 71 [2] a4 77 [2] b8 70 [2] a4 5f }

  condition:
    any of them
}