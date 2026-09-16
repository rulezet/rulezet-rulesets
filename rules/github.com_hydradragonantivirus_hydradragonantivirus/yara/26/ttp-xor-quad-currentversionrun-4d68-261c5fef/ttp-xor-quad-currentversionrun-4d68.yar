rule TTP_XOR_QUAD_CurrentVersionRun_4d68 {
  strings:
    $key_4d68 = { 1e 07 [2] 3a 09 [2] 11 25 [2] 3f 07 [2] 2b 1c [2] 24 06 [2] 3a 1b [2] 38 1a [2] 23 1c [2] 3f 1b [2] 23 34 }

  condition:
    any of them
}