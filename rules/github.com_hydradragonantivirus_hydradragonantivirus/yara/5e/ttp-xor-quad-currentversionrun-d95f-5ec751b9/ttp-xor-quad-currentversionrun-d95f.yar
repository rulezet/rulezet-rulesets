rule TTP_XOR_QUAD_CurrentVersionRun_d95f {
  strings:
    $key_d95f = { 8a 30 [2] ae 3e [2] 85 12 [2] ab 30 [2] bf 2b [2] b0 31 [2] ae 2c [2] ac 2d [2] b7 2b [2] ab 2c [2] b7 03 }

  condition:
    any of them
}