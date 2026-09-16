rule TTP_XOR_QUAD_CurrentVersionRun_2975 {
  strings:
    $key_2975 = { 7a 1a [2] 5e 14 [2] 75 38 [2] 5b 1a [2] 4f 01 [2] 40 1b [2] 5e 06 [2] 5c 07 [2] 47 01 [2] 5b 06 [2] 47 29 }

  condition:
    any of them
}