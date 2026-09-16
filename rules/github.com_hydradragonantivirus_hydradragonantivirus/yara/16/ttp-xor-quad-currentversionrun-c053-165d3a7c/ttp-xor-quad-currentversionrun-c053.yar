rule TTP_XOR_QUAD_CurrentVersionRun_c053 {
  strings:
    $key_c053 = { 93 3c [2] b7 32 [2] 9c 1e [2] b2 3c [2] a6 27 [2] a9 3d [2] b7 20 [2] b5 21 [2] ae 27 [2] b2 20 [2] ae 0f }

  condition:
    any of them
}