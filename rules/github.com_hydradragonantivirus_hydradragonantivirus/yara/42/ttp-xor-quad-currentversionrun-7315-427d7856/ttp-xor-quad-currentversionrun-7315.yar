rule TTP_XOR_QUAD_CurrentVersionRun_7315 {
  strings:
    $key_7315 = { 20 7a [2] 04 74 [2] 2f 58 [2] 01 7a [2] 15 61 [2] 1a 7b [2] 04 66 [2] 06 67 [2] 1d 61 [2] 01 66 [2] 1d 49 }

  condition:
    any of them
}