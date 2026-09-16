rule TTP_XOR_QUAD_CurrentVersionRun_5575 {
  strings:
    $key_5575 = { 06 1a [2] 22 14 [2] 09 38 [2] 27 1a [2] 33 01 [2] 3c 1b [2] 22 06 [2] 20 07 [2] 3b 01 [2] 27 06 [2] 3b 29 }

  condition:
    any of them
}