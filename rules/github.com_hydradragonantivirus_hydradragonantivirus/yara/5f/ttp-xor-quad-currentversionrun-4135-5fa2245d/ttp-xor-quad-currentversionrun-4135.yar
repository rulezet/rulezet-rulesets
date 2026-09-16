rule TTP_XOR_QUAD_CurrentVersionRun_4135 {
  strings:
    $key_4135 = { 12 5a [2] 36 54 [2] 1d 78 [2] 33 5a [2] 27 41 [2] 28 5b [2] 36 46 [2] 34 47 [2] 2f 41 [2] 33 46 [2] 2f 69 }

  condition:
    any of them
}