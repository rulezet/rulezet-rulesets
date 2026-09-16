rule TTP_XOR_QUAD_CurrentVersionRun_0867 {
  strings:
    $key_0867 = { 5b 08 [2] 7f 06 [2] 54 2a [2] 7a 08 [2] 6e 13 [2] 61 09 [2] 7f 14 [2] 7d 15 [2] 66 13 [2] 7a 14 [2] 66 3b }

  condition:
    any of them
}