rule TTP_XOR_QUAD_CurrentVersionRun_422a {
  strings:
    $key_422a = { 11 45 [2] 35 4b [2] 1e 67 [2] 30 45 [2] 24 5e [2] 2b 44 [2] 35 59 [2] 37 58 [2] 2c 5e [2] 30 59 [2] 2c 76 }

  condition:
    any of them
}