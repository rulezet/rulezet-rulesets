rule TTP_XOR_QUAD_CurrentVersionRun_db53 {
  strings:
    $key_db53 = { 88 3c [2] ac 32 [2] 87 1e [2] a9 3c [2] bd 27 [2] b2 3d [2] ac 20 [2] ae 21 [2] b5 27 [2] a9 20 [2] b5 0f }

  condition:
    any of them
}