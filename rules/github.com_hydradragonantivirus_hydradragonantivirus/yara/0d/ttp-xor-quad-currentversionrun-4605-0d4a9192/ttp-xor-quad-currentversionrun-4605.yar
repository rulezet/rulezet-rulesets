rule TTP_XOR_QUAD_CurrentVersionRun_4605 {
  strings:
    $key_4605 = { 15 6a [2] 31 64 [2] 1a 48 [2] 34 6a [2] 20 71 [2] 2f 6b [2] 31 76 [2] 33 77 [2] 28 71 [2] 34 76 [2] 28 59 }

  condition:
    any of them
}