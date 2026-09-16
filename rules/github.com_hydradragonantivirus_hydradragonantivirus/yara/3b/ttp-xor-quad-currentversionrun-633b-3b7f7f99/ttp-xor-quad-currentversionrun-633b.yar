rule TTP_XOR_QUAD_CurrentVersionRun_633b {
  strings:
    $key_633b = { 30 54 [2] 14 5a [2] 3f 76 [2] 11 54 [2] 05 4f [2] 0a 55 [2] 14 48 [2] 16 49 [2] 0d 4f [2] 11 48 [2] 0d 67 }

  condition:
    any of them
}