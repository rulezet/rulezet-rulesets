rule TTP_XOR_QUAD_CurrentVersionRun_6f1b {
  strings:
    $key_6f1b = { 3c 74 [2] 18 7a [2] 33 56 [2] 1d 74 [2] 09 6f [2] 06 75 [2] 18 68 [2] 1a 69 [2] 01 6f [2] 1d 68 [2] 01 47 }

  condition:
    any of them
}