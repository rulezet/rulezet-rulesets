rule TTP_XOR_QUAD_CurrentVersionRun_d96f {
  strings:
    $key_d96f = { 8a 00 [2] ae 0e [2] 85 22 [2] ab 00 [2] bf 1b [2] b0 01 [2] ae 1c [2] ac 1d [2] b7 1b [2] ab 1c [2] b7 33 }

  condition:
    any of them
}