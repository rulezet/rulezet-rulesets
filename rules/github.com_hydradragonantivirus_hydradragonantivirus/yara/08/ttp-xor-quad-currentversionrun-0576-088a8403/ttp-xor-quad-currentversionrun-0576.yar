rule TTP_XOR_QUAD_CurrentVersionRun_0576 {
  strings:
    $key_0576 = { 56 19 [2] 72 17 [2] 59 3b [2] 77 19 [2] 63 02 [2] 6c 18 [2] 72 05 [2] 70 04 [2] 6b 02 [2] 77 05 [2] 6b 2a }

  condition:
    any of them
}