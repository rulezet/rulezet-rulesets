rule TTP_XOR_QUAD_CurrentVersionRun_7d79 {
  strings:
    $key_7d79 = { 2e 16 [2] 0a 18 [2] 21 34 [2] 0f 16 [2] 1b 0d [2] 14 17 [2] 0a 0a [2] 08 0b [2] 13 0d [2] 0f 0a [2] 13 25 }

  condition:
    any of them
}