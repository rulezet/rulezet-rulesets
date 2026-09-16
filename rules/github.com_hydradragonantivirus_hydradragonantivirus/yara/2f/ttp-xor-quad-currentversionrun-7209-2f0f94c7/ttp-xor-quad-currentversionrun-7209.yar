rule TTP_XOR_QUAD_CurrentVersionRun_7209 {
  strings:
    $key_7209 = { 21 66 [2] 05 68 [2] 2e 44 [2] 00 66 [2] 14 7d [2] 1b 67 [2] 05 7a [2] 07 7b [2] 1c 7d [2] 00 7a [2] 1c 55 }

  condition:
    any of them
}