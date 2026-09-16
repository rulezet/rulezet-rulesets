rule TTP_XOR_QUAD_CurrentVersionRun_5f1b {
  strings:
    $key_5f1b = { 0c 74 [2] 28 7a [2] 03 56 [2] 2d 74 [2] 39 6f [2] 36 75 [2] 28 68 [2] 2a 69 [2] 31 6f [2] 2d 68 [2] 31 47 }

  condition:
    any of them
}