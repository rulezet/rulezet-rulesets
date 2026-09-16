rule TTP_XOR_QUAD_CurrentVersionRun_0047 {
  strings:
    $key_0047 = { 53 28 [2] 77 26 [2] 5c 0a [2] 72 28 [2] 66 33 [2] 69 29 [2] 77 34 [2] 75 35 [2] 6e 33 [2] 72 34 [2] 6e 1b }

  condition:
    any of them
}