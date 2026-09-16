rule TTP_XOR_QUAD_CurrentVersionRun_db43 {
  strings:
    $key_db43 = { 88 2c [2] ac 22 [2] 87 0e [2] a9 2c [2] bd 37 [2] b2 2d [2] ac 30 [2] ae 31 [2] b5 37 [2] a9 30 [2] b5 1f }

  condition:
    any of them
}