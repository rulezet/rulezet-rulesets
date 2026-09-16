rule TTP_XOR_QUAD_CurrentVersionRun_2454 {
  strings:
    $key_2454 = { 77 3b [2] 53 35 [2] 78 19 [2] 56 3b [2] 42 20 [2] 4d 3a [2] 53 27 [2] 51 26 [2] 4a 20 [2] 56 27 [2] 4a 08 }

  condition:
    any of them
}