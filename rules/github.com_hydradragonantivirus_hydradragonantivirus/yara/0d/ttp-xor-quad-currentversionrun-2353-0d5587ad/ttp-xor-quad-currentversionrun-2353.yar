rule TTP_XOR_QUAD_CurrentVersionRun_2353 {
  strings:
    $key_2353 = { 70 3c [2] 54 32 [2] 7f 1e [2] 51 3c [2] 45 27 [2] 4a 3d [2] 54 20 [2] 56 21 [2] 4d 27 [2] 51 20 [2] 4d 0f }

  condition:
    any of them
}