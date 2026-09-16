rule TTP_XOR_QUAD_CurrentVersionRun_4dfd {
  strings:
    $key_4dfd = { 1e 92 [2] 3a 9c [2] 11 b0 [2] 3f 92 [2] 2b 89 [2] 24 93 [2] 3a 8e [2] 38 8f [2] 23 89 [2] 3f 8e [2] 23 a1 }

  condition:
    any of them
}