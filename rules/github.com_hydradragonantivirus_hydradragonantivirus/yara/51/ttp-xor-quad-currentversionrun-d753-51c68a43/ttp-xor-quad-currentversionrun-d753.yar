rule TTP_XOR_QUAD_CurrentVersionRun_d753 {
  strings:
    $key_d753 = { 84 3c [2] a0 32 [2] 8b 1e [2] a5 3c [2] b1 27 [2] be 3d [2] a0 20 [2] a2 21 [2] b9 27 [2] a5 20 [2] b9 0f }

  condition:
    any of them
}