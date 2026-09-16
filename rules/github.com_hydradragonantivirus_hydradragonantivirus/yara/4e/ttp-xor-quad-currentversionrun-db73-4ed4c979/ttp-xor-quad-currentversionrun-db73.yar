rule TTP_XOR_QUAD_CurrentVersionRun_db73 {
  strings:
    $key_db73 = { 88 1c [2] ac 12 [2] 87 3e [2] a9 1c [2] bd 07 [2] b2 1d [2] ac 00 [2] ae 01 [2] b5 07 [2] a9 00 [2] b5 2f }

  condition:
    any of them
}