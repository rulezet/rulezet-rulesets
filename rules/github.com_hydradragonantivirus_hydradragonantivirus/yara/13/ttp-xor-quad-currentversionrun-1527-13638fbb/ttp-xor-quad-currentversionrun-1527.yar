rule TTP_XOR_QUAD_CurrentVersionRun_1527 {
  strings:
    $key_1527 = { 46 48 [2] 62 46 [2] 49 6a [2] 67 48 [2] 73 53 [2] 7c 49 [2] 62 54 [2] 60 55 [2] 7b 53 [2] 67 54 [2] 7b 7b }

  condition:
    any of them
}