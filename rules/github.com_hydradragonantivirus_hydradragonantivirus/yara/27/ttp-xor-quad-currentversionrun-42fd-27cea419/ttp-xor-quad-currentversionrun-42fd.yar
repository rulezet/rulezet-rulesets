rule TTP_XOR_QUAD_CurrentVersionRun_42fd {
  strings:
    $key_42fd = { 11 92 [2] 35 9c [2] 1e b0 [2] 30 92 [2] 24 89 [2] 2b 93 [2] 35 8e [2] 37 8f [2] 2c 89 [2] 30 8e [2] 2c a1 }

  condition:
    any of them
}