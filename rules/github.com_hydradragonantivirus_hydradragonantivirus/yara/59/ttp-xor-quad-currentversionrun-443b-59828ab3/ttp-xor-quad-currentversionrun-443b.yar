rule TTP_XOR_QUAD_CurrentVersionRun_443b {
  strings:
    $key_443b = { 17 54 [2] 33 5a [2] 18 76 [2] 36 54 [2] 22 4f [2] 2d 55 [2] 33 48 [2] 31 49 [2] 2a 4f [2] 36 48 [2] 2a 67 }

  condition:
    any of them
}