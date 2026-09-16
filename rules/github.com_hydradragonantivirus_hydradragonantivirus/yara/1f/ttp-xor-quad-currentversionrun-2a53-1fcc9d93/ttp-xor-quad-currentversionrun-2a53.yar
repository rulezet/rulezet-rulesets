rule TTP_XOR_QUAD_CurrentVersionRun_2a53 {
  strings:
    $key_2a53 = { 79 3c [2] 5d 32 [2] 76 1e [2] 58 3c [2] 4c 27 [2] 43 3d [2] 5d 20 [2] 5f 21 [2] 44 27 [2] 58 20 [2] 44 0f }

  condition:
    any of them
}