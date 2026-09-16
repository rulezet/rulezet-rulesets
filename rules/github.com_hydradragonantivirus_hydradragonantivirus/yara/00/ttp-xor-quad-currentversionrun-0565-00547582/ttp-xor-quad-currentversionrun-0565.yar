rule TTP_XOR_QUAD_CurrentVersionRun_0565 {
  strings:
    $key_0565 = { 56 0a [2] 72 04 [2] 59 28 [2] 77 0a [2] 63 11 [2] 6c 0b [2] 72 16 [2] 70 17 [2] 6b 11 [2] 77 16 [2] 6b 39 }

  condition:
    any of them
}