rule TTP_XOR_QUAD_CurrentVersionRun_2127 {
  strings:
    $key_2127 = { 72 48 [2] 56 46 [2] 7d 6a [2] 53 48 [2] 47 53 [2] 48 49 [2] 56 54 [2] 54 55 [2] 4f 53 [2] 53 54 [2] 4f 7b }

  condition:
    any of them
}