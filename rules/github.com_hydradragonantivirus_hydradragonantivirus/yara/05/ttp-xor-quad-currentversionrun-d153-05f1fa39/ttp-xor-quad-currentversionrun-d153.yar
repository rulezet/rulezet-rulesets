rule TTP_XOR_QUAD_CurrentVersionRun_d153 {
  strings:
    $key_d153 = { 82 3c [2] a6 32 [2] 8d 1e [2] a3 3c [2] b7 27 [2] b8 3d [2] a6 20 [2] a4 21 [2] bf 27 [2] a3 20 [2] bf 0f }

  condition:
    any of them
}