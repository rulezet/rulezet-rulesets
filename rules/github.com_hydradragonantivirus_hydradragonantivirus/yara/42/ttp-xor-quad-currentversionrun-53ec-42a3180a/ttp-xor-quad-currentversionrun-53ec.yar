rule TTP_XOR_QUAD_CurrentVersionRun_53ec {
  strings:
    $key_53ec = { 00 83 [2] 24 8d [2] 0f a1 [2] 21 83 [2] 35 98 [2] 3a 82 [2] 24 9f [2] 26 9e [2] 3d 98 [2] 21 9f [2] 3d b0 }

  condition:
    any of them
}