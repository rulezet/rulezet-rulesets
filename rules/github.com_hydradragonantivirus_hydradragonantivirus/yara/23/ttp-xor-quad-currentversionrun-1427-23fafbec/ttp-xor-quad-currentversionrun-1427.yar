rule TTP_XOR_QUAD_CurrentVersionRun_1427 {
  strings:
    $key_1427 = { 47 48 [2] 63 46 [2] 48 6a [2] 66 48 [2] 72 53 [2] 7d 49 [2] 63 54 [2] 61 55 [2] 7a 53 [2] 66 54 [2] 7a 7b }

  condition:
    any of them
}