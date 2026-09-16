rule TTP_XOR_QUAD_CurrentVersionRun_2145 {
  strings:
    $key_2145 = { 72 2a [2] 56 24 [2] 7d 08 [2] 53 2a [2] 47 31 [2] 48 2b [2] 56 36 [2] 54 37 [2] 4f 31 [2] 53 36 [2] 4f 19 }

  condition:
    any of them
}