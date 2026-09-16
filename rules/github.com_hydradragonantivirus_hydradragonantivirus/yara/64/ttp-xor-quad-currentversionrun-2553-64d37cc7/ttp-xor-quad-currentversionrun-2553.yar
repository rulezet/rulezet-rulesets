rule TTP_XOR_QUAD_CurrentVersionRun_2553 {
  strings:
    $key_2553 = { 76 3c [2] 52 32 [2] 79 1e [2] 57 3c [2] 43 27 [2] 4c 3d [2] 52 20 [2] 50 21 [2] 4b 27 [2] 57 20 [2] 4b 0f }

  condition:
    any of them
}