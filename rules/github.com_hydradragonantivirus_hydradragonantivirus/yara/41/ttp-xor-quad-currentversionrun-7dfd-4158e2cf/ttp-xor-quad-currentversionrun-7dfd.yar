rule TTP_XOR_QUAD_CurrentVersionRun_7dfd {
  strings:
    $key_7dfd = { 2e 92 [2] 0a 9c [2] 21 b0 [2] 0f 92 [2] 1b 89 [2] 14 93 [2] 0a 8e [2] 08 8f [2] 13 89 [2] 0f 8e [2] 13 a1 }

  condition:
    any of them
}