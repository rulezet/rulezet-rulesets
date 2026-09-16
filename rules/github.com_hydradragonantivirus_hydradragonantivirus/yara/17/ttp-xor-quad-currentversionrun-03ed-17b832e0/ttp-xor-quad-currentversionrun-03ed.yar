rule TTP_XOR_QUAD_CurrentVersionRun_03ed {
  strings:
    $key_03ed = { 50 82 [2] 74 8c [2] 5f a0 [2] 71 82 [2] 65 99 [2] 6a 83 [2] 74 9e [2] 76 9f [2] 6d 99 [2] 71 9e [2] 6d b1 }

  condition:
    any of them
}