rule TTP_XOR_QUAD_CurrentVersionRun_0545 {
  strings:
    $key_0545 = { 56 2a [2] 72 24 [2] 59 08 [2] 77 2a [2] 63 31 [2] 6c 2b [2] 72 36 [2] 70 37 [2] 6b 31 [2] 77 36 [2] 6b 19 }

  condition:
    any of them
}