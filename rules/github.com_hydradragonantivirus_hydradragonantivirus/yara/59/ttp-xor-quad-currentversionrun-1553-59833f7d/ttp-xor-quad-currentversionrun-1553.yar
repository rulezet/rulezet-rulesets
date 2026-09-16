rule TTP_XOR_QUAD_CurrentVersionRun_1553 {
  strings:
    $key_1553 = { 46 3c [2] 62 32 [2] 49 1e [2] 67 3c [2] 73 27 [2] 7c 3d [2] 62 20 [2] 60 21 [2] 7b 27 [2] 67 20 [2] 7b 0f }

  condition:
    any of them
}