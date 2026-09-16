rule TTP_XOR_QUAD_CurrentVersionRun_745d {
  strings:
    $key_745d = { 27 32 [2] 03 3c [2] 28 10 [2] 06 32 [2] 12 29 [2] 1d 33 [2] 03 2e [2] 01 2f [2] 1a 29 [2] 06 2e [2] 1a 01 }

  condition:
    any of them
}