rule TTP_XOR_QUAD_CurrentVersionRun_53ed {
  strings:
    $key_53ed = { 00 82 [2] 24 8c [2] 0f a0 [2] 21 82 [2] 35 99 [2] 3a 83 [2] 24 9e [2] 26 9f [2] 3d 99 [2] 21 9e [2] 3d b1 }

  condition:
    any of them
}