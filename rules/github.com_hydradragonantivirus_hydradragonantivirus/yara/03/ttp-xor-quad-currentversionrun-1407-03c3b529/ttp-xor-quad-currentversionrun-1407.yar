rule TTP_XOR_QUAD_CurrentVersionRun_1407 {
  strings:
    $key_1407 = { 47 68 [2] 63 66 [2] 48 4a [2] 66 68 [2] 72 73 [2] 7d 69 [2] 63 74 [2] 61 75 [2] 7a 73 [2] 66 74 [2] 7a 5b }

  condition:
    any of them
}