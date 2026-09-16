rule TTP_XOR_QUAD_CurrentVersionRun_0577 {
  strings:
    $key_0577 = { 56 18 [2] 72 16 [2] 59 3a [2] 77 18 [2] 63 03 [2] 6c 19 [2] 72 04 [2] 70 05 [2] 6b 03 [2] 77 04 [2] 6b 2b }

  condition:
    any of them
}