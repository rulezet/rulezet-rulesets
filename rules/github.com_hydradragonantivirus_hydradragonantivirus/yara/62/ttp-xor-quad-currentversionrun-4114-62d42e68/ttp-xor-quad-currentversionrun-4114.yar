rule TTP_XOR_QUAD_CurrentVersionRun_4114 {
  strings:
    $key_4114 = { 12 7b [2] 36 75 [2] 1d 59 [2] 33 7b [2] 27 60 [2] 28 7a [2] 36 67 [2] 34 66 [2] 2f 60 [2] 33 67 [2] 2f 48 }

  condition:
    any of them
}