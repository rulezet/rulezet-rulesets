rule TTP_XOR_QUAD_CurrentVersionRun_4975 {
  strings:
    $key_4975 = { 1a 1a [2] 3e 14 [2] 15 38 [2] 3b 1a [2] 2f 01 [2] 20 1b [2] 3e 06 [2] 3c 07 [2] 27 01 [2] 3b 06 [2] 27 29 }

  condition:
    any of them
}