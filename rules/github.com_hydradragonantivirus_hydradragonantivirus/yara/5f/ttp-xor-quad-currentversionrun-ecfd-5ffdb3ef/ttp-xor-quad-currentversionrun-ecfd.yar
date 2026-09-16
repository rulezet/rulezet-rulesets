rule TTP_XOR_QUAD_CurrentVersionRun_ecfd {
  strings:
    $key_ecfd = { bf 92 [2] 9b 9c [2] b0 b0 [2] 9e 92 [2] 8a 89 [2] 85 93 [2] 9b 8e [2] 99 8f [2] 82 89 [2] 9e 8e [2] 82 a1 }

  condition:
    any of them
}