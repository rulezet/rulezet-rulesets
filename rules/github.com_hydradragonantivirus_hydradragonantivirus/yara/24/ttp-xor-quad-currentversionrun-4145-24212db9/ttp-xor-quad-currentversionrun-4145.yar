rule TTP_XOR_QUAD_CurrentVersionRun_4145 {
  strings:
    $key_4145 = { 12 2a [2] 36 24 [2] 1d 08 [2] 33 2a [2] 27 31 [2] 28 2b [2] 36 36 [2] 34 37 [2] 2f 31 [2] 33 36 [2] 2f 19 }

  condition:
    any of them
}