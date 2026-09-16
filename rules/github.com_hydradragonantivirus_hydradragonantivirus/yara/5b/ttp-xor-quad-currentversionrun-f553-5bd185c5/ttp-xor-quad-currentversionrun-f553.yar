rule TTP_XOR_QUAD_CurrentVersionRun_f553 {
  strings:
    $key_f553 = { a6 3c [2] 82 32 [2] a9 1e [2] 87 3c [2] 93 27 [2] 9c 3d [2] 82 20 [2] 80 21 [2] 9b 27 [2] 87 20 [2] 9b 0f }

  condition:
    any of them
}