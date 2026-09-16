rule TTP_XOR_QUAD_CurrentVersionRun_0568 {
  strings:
    $key_0568 = { 56 07 [2] 72 09 [2] 59 25 [2] 77 07 [2] 63 1c [2] 6c 06 [2] 72 1b [2] 70 1a [2] 6b 1c [2] 77 1b [2] 6b 34 }

  condition:
    any of them
}