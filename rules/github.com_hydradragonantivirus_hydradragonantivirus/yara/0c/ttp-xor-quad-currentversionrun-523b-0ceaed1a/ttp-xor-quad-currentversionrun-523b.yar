rule TTP_XOR_QUAD_CurrentVersionRun_523b {
  strings:
    $key_523b = { 01 54 [2] 25 5a [2] 0e 76 [2] 20 54 [2] 34 4f [2] 3b 55 [2] 25 48 [2] 27 49 [2] 3c 4f [2] 20 48 [2] 3c 67 }

  condition:
    any of them
}