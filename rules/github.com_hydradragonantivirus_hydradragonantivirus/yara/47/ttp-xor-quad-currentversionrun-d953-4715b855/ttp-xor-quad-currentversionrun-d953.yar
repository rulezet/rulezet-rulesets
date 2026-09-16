rule TTP_XOR_QUAD_CurrentVersionRun_d953 {
  strings:
    $key_d953 = { 8a 3c [2] ae 32 [2] 85 1e [2] ab 3c [2] bf 27 [2] b0 3d [2] ae 20 [2] ac 21 [2] b7 27 [2] ab 20 [2] b7 0f }

  condition:
    any of them
}