rule TTP_XOR_QUAD_CurrentVersionRun_0f67 {
  strings:
    $key_0f67 = { 5c 08 [2] 78 06 [2] 53 2a [2] 7d 08 [2] 69 13 [2] 66 09 [2] 78 14 [2] 7a 15 [2] 61 13 [2] 7d 14 [2] 61 3b }

  condition:
    any of them
}