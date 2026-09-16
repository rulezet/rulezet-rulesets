rule TTP_XOR_QUAD_CurrentVersionRun_420a {
  strings:
    $key_420a = { 11 65 [2] 35 6b [2] 1e 47 [2] 30 65 [2] 24 7e [2] 2b 64 [2] 35 79 [2] 37 78 [2] 2c 7e [2] 30 79 [2] 2c 56 }

  condition:
    any of them
}