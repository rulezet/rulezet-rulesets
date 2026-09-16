rule TTP_XOR_QUAD_CurrentVersionRun_4104 {
  strings:
    $key_4104 = { 12 6b [2] 36 65 [2] 1d 49 [2] 33 6b [2] 27 70 [2] 28 6a [2] 36 77 [2] 34 76 [2] 2f 70 [2] 33 77 [2] 2f 58 }

  condition:
    any of them
}