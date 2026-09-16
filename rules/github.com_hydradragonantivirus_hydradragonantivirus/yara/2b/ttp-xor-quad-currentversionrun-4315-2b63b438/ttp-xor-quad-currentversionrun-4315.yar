rule TTP_XOR_QUAD_CurrentVersionRun_4315 {
  strings:
    $key_4315 = { 10 7a [2] 34 74 [2] 1f 58 [2] 31 7a [2] 25 61 [2] 2a 7b [2] 34 66 [2] 36 67 [2] 2d 61 [2] 31 66 [2] 2d 49 }

  condition:
    any of them
}