rule TTP_XOR_QUAD_CurrentVersionRun_1b7d {
  strings:
    $key_1b7d = { 48 12 [2] 6c 1c [2] 47 30 [2] 69 12 [2] 7d 09 [2] 72 13 [2] 6c 0e [2] 6e 0f [2] 75 09 [2] 69 0e [2] 75 21 }

  condition:
    any of them
}