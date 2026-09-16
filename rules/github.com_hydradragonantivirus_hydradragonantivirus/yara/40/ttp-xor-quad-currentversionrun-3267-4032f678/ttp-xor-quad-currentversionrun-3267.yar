rule TTP_XOR_QUAD_CurrentVersionRun_3267 {
  strings:
    $key_3267 = { 61 08 [2] 45 06 [2] 6e 2a [2] 40 08 [2] 54 13 [2] 5b 09 [2] 45 14 [2] 47 15 [2] 5c 13 [2] 40 14 [2] 5c 3b }

  condition:
    any of them
}