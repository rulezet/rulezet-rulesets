rule TTP_XOR_QUAD_CurrentVersionRun_1053 {
  strings:
    $key_1053 = { 43 3c [2] 67 32 [2] 4c 1e [2] 62 3c [2] 76 27 [2] 79 3d [2] 67 20 [2] 65 21 [2] 7e 27 [2] 62 20 [2] 7e 0f }

  condition:
    any of them
}