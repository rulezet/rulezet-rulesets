rule TTP_XOR_QUAD_CurrentVersionRun_5015 {
  strings:
    $key_5015 = { 03 7a [2] 27 74 [2] 0c 58 [2] 22 7a [2] 36 61 [2] 39 7b [2] 27 66 [2] 25 67 [2] 3e 61 [2] 22 66 [2] 3e 49 }

  condition:
    any of them
}