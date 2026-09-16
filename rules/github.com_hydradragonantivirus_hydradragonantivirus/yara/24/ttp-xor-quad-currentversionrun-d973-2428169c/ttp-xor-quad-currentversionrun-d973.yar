rule TTP_XOR_QUAD_CurrentVersionRun_d973 {
  strings:
    $key_d973 = { 8a 1c [2] ae 12 [2] 85 3e [2] ab 1c [2] bf 07 [2] b0 1d [2] ae 00 [2] ac 01 [2] b7 07 [2] ab 00 [2] b7 2f }

  condition:
    any of them
}