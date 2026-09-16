rule TTP_XOR_QUAD_CurrentVersionRun_13ed {
  strings:
    $key_13ed = { 40 82 [2] 64 8c [2] 4f a0 [2] 61 82 [2] 75 99 [2] 7a 83 [2] 64 9e [2] 66 9f [2] 7d 99 [2] 61 9e [2] 7d b1 }

  condition:
    any of them
}