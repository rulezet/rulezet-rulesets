rule TTP_XOR_QUAD_CurrentVersionRun_2f53 {
  strings:
    $key_2f53 = { 7c 3c [2] 58 32 [2] 73 1e [2] 5d 3c [2] 49 27 [2] 46 3d [2] 58 20 [2] 5a 21 [2] 41 27 [2] 5d 20 [2] 41 0f }

  condition:
    any of them
}