rule TTP_XOR_QUAD_CurrentVersionRun_6a04 {
  strings:
    $key_6a04 = { 39 6b [2] 1d 65 [2] 36 49 [2] 18 6b [2] 0c 70 [2] 03 6a [2] 1d 77 [2] 1f 76 [2] 04 70 [2] 18 77 [2] 04 58 }

  condition:
    any of them
}