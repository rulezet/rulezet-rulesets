rule TTP_XOR_QUAD_CurrentVersionRun_3e27 {
  strings:
    $key_3e27 = { 6d 48 [2] 49 46 [2] 62 6a [2] 4c 48 [2] 58 53 [2] 57 49 [2] 49 54 [2] 4b 55 [2] 50 53 [2] 4c 54 [2] 50 7b }

  condition:
    any of them
}