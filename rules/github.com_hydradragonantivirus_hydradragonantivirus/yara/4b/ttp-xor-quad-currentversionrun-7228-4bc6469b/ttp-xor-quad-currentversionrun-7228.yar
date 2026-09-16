rule TTP_XOR_QUAD_CurrentVersionRun_7228 {
  strings:
    $key_7228 = { 21 47 [2] 05 49 [2] 2e 65 [2] 00 47 [2] 14 5c [2] 1b 46 [2] 05 5b [2] 07 5a [2] 1c 5c [2] 00 5b [2] 1c 74 }

  condition:
    any of them
}