rule TTP_XOR_QUAD_CurrentVersionRun_1c53 {
  strings:
    $key_1c53 = { 4f 3c [2] 6b 32 [2] 40 1e [2] 6e 3c [2] 7a 27 [2] 75 3d [2] 6b 20 [2] 69 21 [2] 72 27 [2] 6e 20 [2] 72 0f }

  condition:
    any of them
}