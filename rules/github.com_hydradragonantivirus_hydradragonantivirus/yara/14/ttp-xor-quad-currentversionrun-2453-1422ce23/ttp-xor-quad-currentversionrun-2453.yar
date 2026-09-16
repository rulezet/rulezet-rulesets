rule TTP_XOR_QUAD_CurrentVersionRun_2453 {
  strings:
    $key_2453 = { 77 3c [2] 53 32 [2] 78 1e [2] 56 3c [2] 42 27 [2] 4d 3d [2] 53 20 [2] 51 21 [2] 4a 27 [2] 56 20 [2] 4a 0f }

  condition:
    any of them
}