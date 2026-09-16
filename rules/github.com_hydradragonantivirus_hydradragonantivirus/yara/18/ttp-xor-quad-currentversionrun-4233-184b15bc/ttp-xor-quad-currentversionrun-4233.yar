rule TTP_XOR_QUAD_CurrentVersionRun_4233 {
  strings:
    $key_4233 = { 11 5c [2] 35 52 [2] 1e 7e [2] 30 5c [2] 24 47 [2] 2b 5d [2] 35 40 [2] 37 41 [2] 2c 47 [2] 30 40 [2] 2c 6f }

  condition:
    any of them
}