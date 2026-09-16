rule TTP_XOR_QUAD_CurrentVersionRun_4714 {
  strings:
    $key_4714 = { 14 7b [2] 30 75 [2] 1b 59 [2] 35 7b [2] 21 60 [2] 2e 7a [2] 30 67 [2] 32 66 [2] 29 60 [2] 35 67 [2] 29 48 }

  condition:
    any of them
}