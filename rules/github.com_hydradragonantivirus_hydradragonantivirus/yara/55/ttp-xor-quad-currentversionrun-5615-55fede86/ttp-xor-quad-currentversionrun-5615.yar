rule TTP_XOR_QUAD_CurrentVersionRun_5615 {
  strings:
    $key_5615 = { 05 7a [2] 21 74 [2] 0a 58 [2] 24 7a [2] 30 61 [2] 3f 7b [2] 21 66 [2] 23 67 [2] 38 61 [2] 24 66 [2] 38 49 }

  condition:
    any of them
}