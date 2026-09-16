rule TTP_XOR_QUAD_CurrentVersionRun_653b {
  strings:
    $key_653b = { 36 54 [2] 12 5a [2] 39 76 [2] 17 54 [2] 03 4f [2] 0c 55 [2] 12 48 [2] 10 49 [2] 0b 4f [2] 17 48 [2] 0b 67 }

  condition:
    any of them
}