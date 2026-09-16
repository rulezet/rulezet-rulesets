rule TTP_XOR_QUAD_CurrentVersionRun_7cfd {
  strings:
    $key_7cfd = { 2f 92 [2] 0b 9c [2] 20 b0 [2] 0e 92 [2] 1a 89 [2] 15 93 [2] 0b 8e [2] 09 8f [2] 12 89 [2] 0e 8e [2] 12 a1 }

  condition:
    any of them
}