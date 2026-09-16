rule TTP_XOR_QUAD_CurrentVersionRun_c753 {
  strings:
    $key_c753 = { 94 3c [2] b0 32 [2] 9b 1e [2] b5 3c [2] a1 27 [2] ae 3d [2] b0 20 [2] b2 21 [2] a9 27 [2] b5 20 [2] a9 0f }

  condition:
    any of them
}