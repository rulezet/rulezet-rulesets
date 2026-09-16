rule TTP_XOR_QUAD_CurrentVersionRun_4754 {
  strings:
    $key_4754 = { 14 3b [2] 30 35 [2] 1b 19 [2] 35 3b [2] 21 20 [2] 2e 3a [2] 30 27 [2] 32 26 [2] 29 20 [2] 35 27 [2] 29 08 }

  condition:
    any of them
}