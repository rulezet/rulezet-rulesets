rule TTP_XOR_QUAD_CurrentVersionRun_4115 {
  strings:
    $key_4115 = { 12 7a [2] 36 74 [2] 1d 58 [2] 33 7a [2] 27 61 [2] 28 7b [2] 36 66 [2] 34 67 [2] 2f 61 [2] 33 66 [2] 2f 49 }

  condition:
    any of them
}