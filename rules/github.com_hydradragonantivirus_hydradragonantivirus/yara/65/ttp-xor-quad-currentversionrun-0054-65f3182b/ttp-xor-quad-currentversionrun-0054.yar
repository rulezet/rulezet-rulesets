rule TTP_XOR_QUAD_CurrentVersionRun_0054 {
  strings:
    $key_0054 = { 53 3b [2] 77 35 [2] 5c 19 [2] 72 3b [2] 66 20 [2] 69 3a [2] 77 27 [2] 75 26 [2] 6e 20 [2] 72 27 [2] 6e 08 }

  condition:
    any of them
}