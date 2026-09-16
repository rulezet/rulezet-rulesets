rule TTP_XOR_QUAD_CurrentVersionRun_7234 {
  strings:
    $key_7234 = { 21 5b [2] 05 55 [2] 2e 79 [2] 00 5b [2] 14 40 [2] 1b 5a [2] 05 47 [2] 07 46 [2] 1c 40 [2] 00 47 [2] 1c 68 }

  condition:
    any of them
}