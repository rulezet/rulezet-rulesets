rule TTP_XOR_QUAD_CurrentVersionRun_5553 {
  strings:
    $key_5553 = { 06 3c [2] 22 32 [2] 09 1e [2] 27 3c [2] 33 27 [2] 3c 3d [2] 22 20 [2] 20 21 [2] 3b 27 [2] 27 20 [2] 3b 0f }

  condition:
    any of them
}