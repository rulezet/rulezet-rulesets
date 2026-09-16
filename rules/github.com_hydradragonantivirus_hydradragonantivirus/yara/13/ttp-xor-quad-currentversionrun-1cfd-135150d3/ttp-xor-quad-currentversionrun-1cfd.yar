rule TTP_XOR_QUAD_CurrentVersionRun_1cfd {
  strings:
    $key_1cfd = { 4f 92 [2] 6b 9c [2] 40 b0 [2] 6e 92 [2] 7a 89 [2] 75 93 [2] 6b 8e [2] 69 8f [2] 72 89 [2] 6e 8e [2] 72 a1 }

  condition:
    any of them
}