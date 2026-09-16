rule TTP_XOR_QUAD_CurrentVersionRun_4124 {
  strings:
    $key_4124 = { 12 4b [2] 36 45 [2] 1d 69 [2] 33 4b [2] 27 50 [2] 28 4a [2] 36 57 [2] 34 56 [2] 2f 50 [2] 33 57 [2] 2f 78 }

  condition:
    any of them
}