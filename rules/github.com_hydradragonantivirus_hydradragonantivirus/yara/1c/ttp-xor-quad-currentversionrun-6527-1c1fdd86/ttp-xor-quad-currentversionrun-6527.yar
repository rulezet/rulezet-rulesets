rule TTP_XOR_QUAD_CurrentVersionRun_6527 {
  strings:
    $key_6527 = { 36 48 [2] 12 46 [2] 39 6a [2] 17 48 [2] 03 53 [2] 0c 49 [2] 12 54 [2] 10 55 [2] 0b 53 [2] 17 54 [2] 0b 7b }

  condition:
    any of them
}