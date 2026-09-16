rule TTP_XOR_QUAD_CurrentVersionRun_422d {
  strings:
    $key_422d = { 11 42 [2] 35 4c [2] 1e 60 [2] 30 42 [2] 24 59 [2] 2b 43 [2] 35 5e [2] 37 5f [2] 2c 59 [2] 30 5e [2] 2c 71 }

  condition:
    any of them
}