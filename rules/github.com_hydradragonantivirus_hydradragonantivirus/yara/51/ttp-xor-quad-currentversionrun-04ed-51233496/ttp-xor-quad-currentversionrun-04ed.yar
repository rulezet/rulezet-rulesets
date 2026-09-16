rule TTP_XOR_QUAD_CurrentVersionRun_04ed {
  strings:
    $key_04ed = { 57 82 [2] 73 8c [2] 58 a0 [2] 76 82 [2] 62 99 [2] 6d 83 [2] 73 9e [2] 71 9f [2] 6a 99 [2] 76 9e [2] 6a b1 }

  condition:
    any of them
}