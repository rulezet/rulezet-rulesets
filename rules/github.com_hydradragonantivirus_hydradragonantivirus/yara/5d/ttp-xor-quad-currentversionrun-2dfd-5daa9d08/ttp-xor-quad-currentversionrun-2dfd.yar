rule TTP_XOR_QUAD_CurrentVersionRun_2dfd {
  strings:
    $key_2dfd = { 7e 92 [2] 5a 9c [2] 71 b0 [2] 5f 92 [2] 4b 89 [2] 44 93 [2] 5a 8e [2] 58 8f [2] 43 89 [2] 5f 8e [2] 43 a1 }

  condition:
    any of them
}