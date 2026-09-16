rule TTP_XOR_QUAD_CurrentVersionRun_7d68 {
  strings:
    $key_7d68 = { 2e 07 [2] 0a 09 [2] 21 25 [2] 0f 07 [2] 1b 1c [2] 14 06 [2] 0a 1b [2] 08 1a [2] 13 1c [2] 0f 1b [2] 13 34 }

  condition:
    any of them
}