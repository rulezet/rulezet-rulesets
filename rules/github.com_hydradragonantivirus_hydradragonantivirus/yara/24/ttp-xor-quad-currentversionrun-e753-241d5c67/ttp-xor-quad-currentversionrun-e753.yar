rule TTP_XOR_QUAD_CurrentVersionRun_e753 {
  strings:
    $key_e753 = { b4 3c [2] 90 32 [2] bb 1e [2] 95 3c [2] 81 27 [2] 8e 3d [2] 90 20 [2] 92 21 [2] 89 27 [2] 95 20 [2] 89 0f }

  condition:
    any of them
}