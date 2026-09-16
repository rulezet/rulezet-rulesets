rule TTP_XOR_QUAD_CurrentVersionRun_7604 {
  strings:
    $key_7604 = { 25 6b [2] 01 65 [2] 2a 49 [2] 04 6b [2] 10 70 [2] 1f 6a [2] 01 77 [2] 03 76 [2] 18 70 [2] 04 77 [2] 18 58 }

  condition:
    any of them
}