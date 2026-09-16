rule TTP_XOR_QUAD_CurrentVersionRun_0044 {
  strings:
    $key_0044 = { 53 2b [2] 77 25 [2] 5c 09 [2] 72 2b [2] 66 30 [2] 69 2a [2] 77 37 [2] 75 36 [2] 6e 30 [2] 72 37 [2] 6e 18 }

  condition:
    any of them
}