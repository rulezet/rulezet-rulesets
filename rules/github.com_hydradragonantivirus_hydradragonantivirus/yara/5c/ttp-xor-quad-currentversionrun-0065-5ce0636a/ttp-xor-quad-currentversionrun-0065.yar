rule TTP_XOR_QUAD_CurrentVersionRun_0065 {
  strings:
    $key_0065 = { 53 0a [2] 77 04 [2] 5c 28 [2] 72 0a [2] 66 11 [2] 69 0b [2] 77 16 [2] 75 17 [2] 6e 11 [2] 72 16 [2] 6e 39 }

  condition:
    any of them
}