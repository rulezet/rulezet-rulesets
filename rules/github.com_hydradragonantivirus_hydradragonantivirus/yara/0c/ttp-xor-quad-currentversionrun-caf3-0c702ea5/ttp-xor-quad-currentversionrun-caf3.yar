rule TTP_XOR_QUAD_CurrentVersionRun_caf3 {
  strings:
    $key_caf3 = { 99 9c [2] bd 92 [2] 96 be [2] b8 9c [2] ac 87 [2] a3 9d [2] bd 80 [2] bf 81 [2] a4 87 [2] b8 80 [2] a4 af }

  condition:
    any of them
}