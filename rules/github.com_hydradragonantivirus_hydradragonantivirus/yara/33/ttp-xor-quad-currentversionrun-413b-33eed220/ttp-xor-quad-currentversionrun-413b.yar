rule TTP_XOR_QUAD_CurrentVersionRun_413b {
  strings:
    $key_413b = { 12 54 [2] 36 5a [2] 1d 76 [2] 33 54 [2] 27 4f [2] 28 55 [2] 36 48 [2] 34 49 [2] 2f 4f [2] 33 48 [2] 2f 67 }

  condition:
    any of them
}