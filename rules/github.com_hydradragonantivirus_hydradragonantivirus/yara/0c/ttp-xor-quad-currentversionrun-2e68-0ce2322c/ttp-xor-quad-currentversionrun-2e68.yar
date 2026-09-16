rule TTP_XOR_QUAD_CurrentVersionRun_2e68 {
  strings:
    $key_2e68 = { 7d 07 [2] 59 09 [2] 72 25 [2] 5c 07 [2] 48 1c [2] 47 06 [2] 59 1b [2] 5b 1a [2] 40 1c [2] 5c 1b [2] 40 34 }

  condition:
    any of them
}