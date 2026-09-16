rule TTP_XOR_QUAD_CurrentVersionRun_63ed {
  strings:
    $key_63ed = { 30 82 [2] 14 8c [2] 3f a0 [2] 11 82 [2] 05 99 [2] 0a 83 [2] 14 9e [2] 16 9f [2] 0d 99 [2] 11 9e [2] 0d b1 }

  condition:
    any of them
}