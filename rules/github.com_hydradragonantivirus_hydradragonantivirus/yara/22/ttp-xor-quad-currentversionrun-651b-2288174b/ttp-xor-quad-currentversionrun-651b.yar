rule TTP_XOR_QUAD_CurrentVersionRun_651b {
  strings:
    $key_651b = { 36 74 [2] 12 7a [2] 39 56 [2] 17 74 [2] 03 6f [2] 0c 75 [2] 12 68 [2] 10 69 [2] 0b 6f [2] 17 68 [2] 0b 47 }

  condition:
    any of them
}