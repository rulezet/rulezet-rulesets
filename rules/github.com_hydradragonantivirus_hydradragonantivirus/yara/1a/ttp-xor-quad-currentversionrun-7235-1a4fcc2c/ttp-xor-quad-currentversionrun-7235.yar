rule TTP_XOR_QUAD_CurrentVersionRun_7235 {
  strings:
    $key_7235 = { 21 5a [2] 05 54 [2] 2e 78 [2] 00 5a [2] 14 41 [2] 1b 5b [2] 05 46 [2] 07 47 [2] 1c 41 [2] 00 46 [2] 1c 69 }

  condition:
    any of them
}