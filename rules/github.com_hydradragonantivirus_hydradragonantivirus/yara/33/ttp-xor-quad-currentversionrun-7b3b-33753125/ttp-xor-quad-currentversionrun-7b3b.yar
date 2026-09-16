rule TTP_XOR_QUAD_CurrentVersionRun_7b3b {
  strings:
    $key_7b3b = { 28 54 [2] 0c 5a [2] 27 76 [2] 09 54 [2] 1d 4f [2] 12 55 [2] 0c 48 [2] 0e 49 [2] 15 4f [2] 09 48 [2] 15 67 }

  condition:
    any of them
}