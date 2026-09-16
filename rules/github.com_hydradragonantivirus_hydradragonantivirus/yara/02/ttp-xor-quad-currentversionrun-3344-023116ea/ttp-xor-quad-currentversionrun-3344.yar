rule TTP_XOR_QUAD_CurrentVersionRun_3344 {
  strings:
    $key_3344 = { 60 2b [2] 44 25 [2] 6f 09 [2] 41 2b [2] 55 30 [2] 5a 2a [2] 44 37 [2] 46 36 [2] 5d 30 [2] 41 37 [2] 5d 18 }

  condition:
    any of them
}