rule TTP_XOR_QUAD_CurrentVersionRun_4e3b {
  strings:
    $key_4e3b = { 1d 54 [2] 39 5a [2] 12 76 [2] 3c 54 [2] 28 4f [2] 27 55 [2] 39 48 [2] 3b 49 [2] 20 4f [2] 3c 48 [2] 20 67 }

  condition:
    any of them
}