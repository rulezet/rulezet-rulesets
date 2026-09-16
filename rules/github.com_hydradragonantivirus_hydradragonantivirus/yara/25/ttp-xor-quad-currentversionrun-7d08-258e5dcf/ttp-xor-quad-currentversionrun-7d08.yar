rule TTP_XOR_QUAD_CurrentVersionRun_7d08 {
  strings:
    $key_7d08 = { 2e 67 [2] 0a 69 [2] 21 45 [2] 0f 67 [2] 1b 7c [2] 14 66 [2] 0a 7b [2] 08 7a [2] 13 7c [2] 0f 7b [2] 13 54 }

  condition:
    any of them
}