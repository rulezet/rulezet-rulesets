rule TTP_XOR_QUAD_CurrentVersionRun_0564 {
  strings:
    $key_0564 = { 56 0b [2] 72 05 [2] 59 29 [2] 77 0b [2] 63 10 [2] 6c 0a [2] 72 17 [2] 70 16 [2] 6b 10 [2] 77 17 [2] 6b 38 }

  condition:
    any of them
}