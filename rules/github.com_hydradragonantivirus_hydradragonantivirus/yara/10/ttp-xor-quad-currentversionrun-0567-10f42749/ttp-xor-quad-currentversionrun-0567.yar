rule TTP_XOR_QUAD_CurrentVersionRun_0567 {
  strings:
    $key_0567 = { 56 08 [2] 72 06 [2] 59 2a [2] 77 08 [2] 63 13 [2] 6c 09 [2] 72 14 [2] 70 15 [2] 6b 13 [2] 77 14 [2] 6b 3b }

  condition:
    any of them
}