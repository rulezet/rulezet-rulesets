rule TTP_XOR_QUAD_CurrentVersionRun_421d {
  strings:
    $key_421d = { 11 72 [2] 35 7c [2] 1e 50 [2] 30 72 [2] 24 69 [2] 2b 73 [2] 35 6e [2] 37 6f [2] 2c 69 [2] 30 6e [2] 2c 41 }

  condition:
    any of them
}