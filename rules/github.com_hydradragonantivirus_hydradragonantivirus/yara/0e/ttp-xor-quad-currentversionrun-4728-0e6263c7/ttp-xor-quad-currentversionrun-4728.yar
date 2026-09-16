rule TTP_XOR_QUAD_CurrentVersionRun_4728 {
  strings:
    $key_4728 = { 14 47 [2] 30 49 [2] 1b 65 [2] 35 47 [2] 21 5c [2] 2e 46 [2] 30 5b [2] 32 5a [2] 29 5c [2] 35 5b [2] 29 74 }

  condition:
    any of them
}