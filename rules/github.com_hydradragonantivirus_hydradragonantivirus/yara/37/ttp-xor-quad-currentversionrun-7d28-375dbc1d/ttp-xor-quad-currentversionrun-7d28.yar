rule TTP_XOR_QUAD_CurrentVersionRun_7d28 {
  strings:
    $key_7d28 = { 2e 47 [2] 0a 49 [2] 21 65 [2] 0f 47 [2] 1b 5c [2] 14 46 [2] 0a 5b [2] 08 5a [2] 13 5c [2] 0f 5b [2] 13 74 }

  condition:
    any of them
}