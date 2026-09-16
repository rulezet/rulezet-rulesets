rule TTP_XOR_QUAD_CurrentVersionRun_2e27 {
  strings:
    $key_2e27 = { 7d 48 [2] 59 46 [2] 72 6a [2] 5c 48 [2] 48 53 [2] 47 49 [2] 59 54 [2] 5b 55 [2] 40 53 [2] 5c 54 [2] 40 7b }

  condition:
    any of them
}