rule TTP_XOR_QUAD_CurrentVersionRun_5a3b {
  strings:
    $key_5a3b = { 09 54 [2] 2d 5a [2] 06 76 [2] 28 54 [2] 3c 4f [2] 33 55 [2] 2d 48 [2] 2f 49 [2] 34 4f [2] 28 48 [2] 34 67 }

  condition:
    any of them
}