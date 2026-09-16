rule TTP_XOR_QUAD_CurrentVersionRun_430b {
  strings:
    $key_430b = { 10 64 [2] 34 6a [2] 1f 46 [2] 31 64 [2] 25 7f [2] 2a 65 [2] 34 78 [2] 36 79 [2] 2d 7f [2] 31 78 [2] 2d 57 }

  condition:
    any of them
}