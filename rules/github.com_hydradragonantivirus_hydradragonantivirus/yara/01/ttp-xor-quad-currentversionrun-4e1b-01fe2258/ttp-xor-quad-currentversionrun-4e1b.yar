rule TTP_XOR_QUAD_CurrentVersionRun_4e1b {
  strings:
    $key_4e1b = { 1d 74 [2] 39 7a [2] 12 56 [2] 3c 74 [2] 28 6f [2] 27 75 [2] 39 68 [2] 3b 69 [2] 20 6f [2] 3c 68 [2] 20 47 }

  condition:
    any of them
}