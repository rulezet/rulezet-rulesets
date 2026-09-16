rule TTP_XOR_QUAD_CurrentVersionRun_73ec {
  strings:
    $key_73ec = { 20 83 [2] 04 8d [2] 2f a1 [2] 01 83 [2] 15 98 [2] 1a 82 [2] 04 9f [2] 06 9e [2] 1d 98 [2] 01 9f [2] 1d b0 }

  condition:
    any of them
}