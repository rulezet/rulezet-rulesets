rule TTP_XOR_QUAD_CurrentVersionRun_4719 {
  strings:
    $key_4719 = { 14 76 [2] 30 78 [2] 1b 54 [2] 35 76 [2] 21 6d [2] 2e 77 [2] 30 6a [2] 32 6b [2] 29 6d [2] 35 6a [2] 29 45 }

  condition:
    any of them
}