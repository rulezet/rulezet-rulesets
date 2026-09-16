rule TTP_XOR_QUAD_CurrentVersionRun_de53 {
  strings:
    $key_de53 = { 8d 3c [2] a9 32 [2] 82 1e [2] ac 3c [2] b8 27 [2] b7 3d [2] a9 20 [2] ab 21 [2] b0 27 [2] ac 20 [2] b0 0f }

  condition:
    any of them
}