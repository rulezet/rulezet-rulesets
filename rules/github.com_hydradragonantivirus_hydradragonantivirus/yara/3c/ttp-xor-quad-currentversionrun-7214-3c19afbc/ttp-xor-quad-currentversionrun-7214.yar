rule TTP_XOR_QUAD_CurrentVersionRun_7214 {
  strings:
    $key_7214 = { 21 7b [2] 05 75 [2] 2e 59 [2] 00 7b [2] 14 60 [2] 1b 7a [2] 05 67 [2] 07 66 [2] 1c 60 [2] 00 67 [2] 1c 48 }

  condition:
    any of them
}