rule TTP_XOR_QUAD_CurrentVersionRun_6f0b {
  strings:
    $key_6f0b = { 3c 64 [2] 18 6a [2] 33 46 [2] 1d 64 [2] 09 7f [2] 06 65 [2] 18 78 [2] 1a 79 [2] 01 7f [2] 1d 78 [2] 01 57 }

  condition:
    any of them
}