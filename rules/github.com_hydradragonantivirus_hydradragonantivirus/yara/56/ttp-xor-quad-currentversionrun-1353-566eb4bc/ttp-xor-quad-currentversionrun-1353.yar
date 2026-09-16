rule TTP_XOR_QUAD_CurrentVersionRun_1353 {
  strings:
    $key_1353 = { 40 3c [2] 64 32 [2] 4f 1e [2] 61 3c [2] 75 27 [2] 7a 3d [2] 64 20 [2] 66 21 [2] 7d 27 [2] 61 20 [2] 7d 0f }

  condition:
    any of them
}