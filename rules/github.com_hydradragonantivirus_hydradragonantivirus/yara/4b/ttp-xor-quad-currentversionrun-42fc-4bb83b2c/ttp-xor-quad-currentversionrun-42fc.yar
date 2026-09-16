rule TTP_XOR_QUAD_CurrentVersionRun_42fc {
  strings:
    $key_42fc = { 11 93 [2] 35 9d [2] 1e b1 [2] 30 93 [2] 24 88 [2] 2b 92 [2] 35 8f [2] 37 8e [2] 2c 88 [2] 30 8f [2] 2c a0 }

  condition:
    any of them
}