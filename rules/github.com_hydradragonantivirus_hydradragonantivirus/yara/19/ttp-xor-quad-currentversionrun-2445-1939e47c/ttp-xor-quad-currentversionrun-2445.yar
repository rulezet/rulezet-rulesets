rule TTP_XOR_QUAD_CurrentVersionRun_2445 {
  strings:
    $key_2445 = { 77 2a [2] 53 24 [2] 78 08 [2] 56 2a [2] 42 31 [2] 4d 2b [2] 53 36 [2] 51 37 [2] 4a 31 [2] 56 36 [2] 4a 19 }

  condition:
    any of them
}