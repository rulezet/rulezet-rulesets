rule TTP_XOR_QUAD_CurrentVersionRun_0566 {
  strings:
    $key_0566 = { 56 09 [2] 72 07 [2] 59 2b [2] 77 09 [2] 63 12 [2] 6c 08 [2] 72 15 [2] 70 14 [2] 6b 12 [2] 77 15 [2] 6b 3a }

  condition:
    any of them
}