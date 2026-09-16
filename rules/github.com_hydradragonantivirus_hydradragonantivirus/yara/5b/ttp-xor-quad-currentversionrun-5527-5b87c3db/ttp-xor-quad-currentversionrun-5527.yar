rule TTP_XOR_QUAD_CurrentVersionRun_5527 {
  strings:
    $key_5527 = { 06 48 [2] 22 46 [2] 09 6a [2] 27 48 [2] 33 53 [2] 3c 49 [2] 22 54 [2] 20 55 [2] 3b 53 [2] 27 54 [2] 3b 7b }

  condition:
    any of them
}