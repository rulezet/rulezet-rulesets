rule TTP_XOR_QUAD_CurrentVersionRun_7208 {
  strings:
    $key_7208 = { 21 67 [2] 05 69 [2] 2e 45 [2] 00 67 [2] 14 7c [2] 1b 66 [2] 05 7b [2] 07 7a [2] 1c 7c [2] 00 7b [2] 1c 54 }

  condition:
    any of them
}