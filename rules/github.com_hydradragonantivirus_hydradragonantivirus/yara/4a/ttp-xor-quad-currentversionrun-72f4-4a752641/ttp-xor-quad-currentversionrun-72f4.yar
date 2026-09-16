rule TTP_XOR_QUAD_CurrentVersionRun_72f4 {
  strings:
    $key_72f4 = { 21 9b [2] 05 95 [2] 2e b9 [2] 00 9b [2] 14 80 [2] 1b 9a [2] 05 87 [2] 07 86 [2] 1c 80 [2] 00 87 [2] 1c a8 }

  condition:
    any of them
}