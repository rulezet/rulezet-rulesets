rule TTP_XOR_QUAD_CurrentVersionRun_4129 {
  strings:
    $key_4129 = { 12 46 [2] 36 48 [2] 1d 64 [2] 33 46 [2] 27 5d [2] 28 47 [2] 36 5a [2] 34 5b [2] 2f 5d [2] 33 5a [2] 2f 75 }

  condition:
    any of them
}