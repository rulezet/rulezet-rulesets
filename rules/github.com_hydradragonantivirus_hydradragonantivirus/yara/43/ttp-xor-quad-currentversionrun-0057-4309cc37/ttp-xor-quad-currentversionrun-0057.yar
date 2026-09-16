rule TTP_XOR_QUAD_CurrentVersionRun_0057 {
  strings:
    $key_0057 = { 53 38 [2] 77 36 [2] 5c 1a [2] 72 38 [2] 66 23 [2] 69 39 [2] 77 24 [2] 75 25 [2] 6e 23 [2] 72 24 [2] 6e 0b }

  condition:
    any of them
}