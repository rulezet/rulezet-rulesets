rule TTP_XOR_QUAD_CurrentVersionRun_f453 {
  strings:
    $key_f453 = { a7 3c [2] 83 32 [2] a8 1e [2] 86 3c [2] 92 27 [2] 9d 3d [2] 83 20 [2] 81 21 [2] 9a 27 [2] 86 20 [2] 9a 0f }

  condition:
    any of them
}