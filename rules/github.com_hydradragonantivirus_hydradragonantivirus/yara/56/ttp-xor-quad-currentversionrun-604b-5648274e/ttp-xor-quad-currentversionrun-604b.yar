rule TTP_XOR_QUAD_CurrentVersionRun_604b {
  strings:
    $key_604b = { 33 24 [2] 17 2a [2] 3c 06 [2] 12 24 [2] 06 3f [2] 09 25 [2] 17 38 [2] 15 39 [2] 0e 3f [2] 12 38 [2] 0e 17 }

  condition:
    any of them
}