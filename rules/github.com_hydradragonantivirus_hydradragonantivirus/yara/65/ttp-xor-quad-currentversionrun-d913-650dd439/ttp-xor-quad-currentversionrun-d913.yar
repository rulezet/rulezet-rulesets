rule TTP_XOR_QUAD_CurrentVersionRun_d913 {
  strings:
    $key_d913 = { 8a 7c [2] ae 72 [2] 85 5e [2] ab 7c [2] bf 67 [2] b0 7d [2] ae 60 [2] ac 61 [2] b7 67 [2] ab 60 [2] b7 4f }

  condition:
    any of them
}