rule TTP_XOR_QUAD_CurrentVersionRun_0079 {
  strings:
    $key_0079 = { 53 16 [2] 77 18 [2] 5c 34 [2] 72 16 [2] 66 0d [2] 69 17 [2] 77 0a [2] 75 0b [2] 6e 0d [2] 72 0a [2] 6e 25 }

  condition:
    any of them
}