rule TTP_XOR_QUAD_CurrentVersionRun_513b {
  strings:
    $key_513b = { 02 54 [2] 26 5a [2] 0d 76 [2] 23 54 [2] 37 4f [2] 38 55 [2] 26 48 [2] 24 49 [2] 3f 4f [2] 23 48 [2] 3f 67 }

  condition:
    any of them
}