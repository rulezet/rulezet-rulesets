rule TTP_XOR_QUAD_CurrentVersionRun_7d29 {
  strings:
    $key_7d29 = { 2e 46 [2] 0a 48 [2] 21 64 [2] 0f 46 [2] 1b 5d [2] 14 47 [2] 0a 5a [2] 08 5b [2] 13 5d [2] 0f 5a [2] 13 75 }

  condition:
    any of them
}