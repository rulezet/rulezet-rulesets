rule TTP_XOR_QUAD_CurrentVersionRun_ecec {
  strings:
    $key_ecec = { bf 83 [2] 9b 8d [2] b0 a1 [2] 9e 83 [2] 8a 98 [2] 85 82 [2] 9b 9f [2] 99 9e [2] 82 98 [2] 9e 9f [2] 82 b0 }

  condition:
    any of them
}