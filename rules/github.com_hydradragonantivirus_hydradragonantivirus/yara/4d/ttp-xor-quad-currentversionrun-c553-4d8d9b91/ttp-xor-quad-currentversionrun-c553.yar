rule TTP_XOR_QUAD_CurrentVersionRun_c553 {
  strings:
    $key_c553 = { 96 3c [2] b2 32 [2] 99 1e [2] b7 3c [2] a3 27 [2] ac 3d [2] b2 20 [2] b0 21 [2] ab 27 [2] b7 20 [2] ab 0f }

  condition:
    any of them
}