rule TTP_XOR_QUAD_CurrentVersionRun_1957 {
  strings:
    $key_1957 = { 4a 38 [2] 6e 36 [2] 45 1a [2] 6b 38 [2] 7f 23 [2] 70 39 [2] 6e 24 [2] 6c 25 [2] 77 23 [2] 6b 24 [2] 77 0b }

  condition:
    any of them
}