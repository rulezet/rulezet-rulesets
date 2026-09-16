rule TTP_XOR_QUAD_CurrentVersionRun_4735 {
  strings:
    $key_4735 = { 14 5a [2] 30 54 [2] 1b 78 [2] 35 5a [2] 21 41 [2] 2e 5b [2] 30 46 [2] 32 47 [2] 29 41 [2] 35 46 [2] 29 69 }

  condition:
    any of them
}