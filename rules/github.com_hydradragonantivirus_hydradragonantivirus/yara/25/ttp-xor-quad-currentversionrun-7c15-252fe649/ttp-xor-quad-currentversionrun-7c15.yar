rule TTP_XOR_QUAD_CurrentVersionRun_7c15 {
  strings:
    $key_7c15 = { 2f 7a [2] 0b 74 [2] 20 58 [2] 0e 7a [2] 1a 61 [2] 15 7b [2] 0b 66 [2] 09 67 [2] 12 61 [2] 0e 66 [2] 12 49 }

  condition:
    any of them
}