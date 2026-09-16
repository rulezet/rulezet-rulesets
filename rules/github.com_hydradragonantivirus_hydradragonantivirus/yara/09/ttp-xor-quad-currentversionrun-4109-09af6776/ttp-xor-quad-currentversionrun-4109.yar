rule TTP_XOR_QUAD_CurrentVersionRun_4109 {
  strings:
    $key_4109 = { 12 66 [2] 36 68 [2] 1d 44 [2] 33 66 [2] 27 7d [2] 28 67 [2] 36 7a [2] 34 7b [2] 2f 7d [2] 33 7a [2] 2f 55 }

  condition:
    any of them
}