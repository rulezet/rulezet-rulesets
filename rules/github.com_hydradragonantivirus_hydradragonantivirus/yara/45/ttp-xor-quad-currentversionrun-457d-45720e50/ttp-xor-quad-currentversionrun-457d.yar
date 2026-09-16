rule TTP_XOR_QUAD_CurrentVersionRun_457d {
  strings:
    $key_457d = { 16 12 [2] 32 1c [2] 19 30 [2] 37 12 [2] 23 09 [2] 2c 13 [2] 32 0e [2] 30 0f [2] 2b 09 [2] 37 0e [2] 2b 21 }

  condition:
    any of them
}