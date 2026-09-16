rule TTP_XOR_QUAD_CurrentVersionRun_4748 {
  strings:
    $key_4748 = { 14 27 [2] 30 29 [2] 1b 05 [2] 35 27 [2] 21 3c [2] 2e 26 [2] 30 3b [2] 32 3a [2] 29 3c [2] 35 3b [2] 29 14 }

  condition:
    any of them
}