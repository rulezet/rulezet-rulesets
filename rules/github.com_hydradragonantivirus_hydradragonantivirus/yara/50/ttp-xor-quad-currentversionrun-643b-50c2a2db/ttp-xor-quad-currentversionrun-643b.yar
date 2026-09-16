rule TTP_XOR_QUAD_CurrentVersionRun_643b {
  strings:
    $key_643b = { 37 54 [2] 13 5a [2] 38 76 [2] 16 54 [2] 02 4f [2] 0d 55 [2] 13 48 [2] 11 49 [2] 0a 4f [2] 16 48 [2] 0a 67 }

  condition:
    any of them
}