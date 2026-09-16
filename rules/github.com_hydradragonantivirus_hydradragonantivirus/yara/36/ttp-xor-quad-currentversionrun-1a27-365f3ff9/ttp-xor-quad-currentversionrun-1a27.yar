rule TTP_XOR_QUAD_CurrentVersionRun_1a27 {
  strings:
    $key_1a27 = { 49 48 [2] 6d 46 [2] 46 6a [2] 68 48 [2] 7c 53 [2] 73 49 [2] 6d 54 [2] 6f 55 [2] 74 53 [2] 68 54 [2] 74 7b }

  condition:
    any of them
}