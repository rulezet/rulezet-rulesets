rule TTP_XOR_QUAD_CurrentVersionRun_4e7d {
  strings:
    $key_4e7d = { 1d 12 [2] 39 1c [2] 12 30 [2] 3c 12 [2] 28 09 [2] 27 13 [2] 39 0e [2] 3b 0f [2] 20 09 [2] 3c 0e [2] 20 21 }

  condition:
    any of them
}