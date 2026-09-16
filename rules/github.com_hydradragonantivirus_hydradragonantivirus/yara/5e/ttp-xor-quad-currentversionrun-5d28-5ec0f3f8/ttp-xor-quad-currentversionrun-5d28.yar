rule TTP_XOR_QUAD_CurrentVersionRun_5d28 {
  strings:
    $key_5d28 = { 0e 47 [2] 2a 49 [2] 01 65 [2] 2f 47 [2] 3b 5c [2] 34 46 [2] 2a 5b [2] 28 5a [2] 33 5c [2] 2f 5b [2] 33 74 }

  condition:
    any of them
}