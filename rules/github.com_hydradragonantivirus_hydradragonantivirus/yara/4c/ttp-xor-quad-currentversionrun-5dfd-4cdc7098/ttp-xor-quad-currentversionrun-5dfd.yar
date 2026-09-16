rule TTP_XOR_QUAD_CurrentVersionRun_5dfd {
  strings:
    $key_5dfd = { 0e 92 [2] 2a 9c [2] 01 b0 [2] 2f 92 [2] 3b 89 [2] 34 93 [2] 2a 8e [2] 28 8f [2] 33 89 [2] 2f 8e [2] 33 a1 }

  condition:
    any of them
}