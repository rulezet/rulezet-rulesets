rule TTP_XOR_QUAD_CurrentVersionRun_440b {
  strings:
    $key_440b = { 17 64 [2] 33 6a [2] 18 46 [2] 36 64 [2] 22 7f [2] 2d 65 [2] 33 78 [2] 31 79 [2] 2a 7f [2] 36 78 [2] 2a 57 }

  condition:
    any of them
}