rule TTP_XOR_QUAD_CurrentVersionRun_73ef {
  strings:
    $key_73ef = { 20 80 [2] 04 8e [2] 2f a2 [2] 01 80 [2] 15 9b [2] 1a 81 [2] 04 9c [2] 06 9d [2] 1d 9b [2] 01 9c [2] 1d b3 }

  condition:
    any of them
}