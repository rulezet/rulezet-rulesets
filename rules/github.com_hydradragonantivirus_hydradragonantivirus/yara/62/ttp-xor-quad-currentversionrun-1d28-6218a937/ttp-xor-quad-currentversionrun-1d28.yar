rule TTP_XOR_QUAD_CurrentVersionRun_1d28 {
  strings:
    $key_1d28 = { 4e 47 [2] 6a 49 [2] 41 65 [2] 6f 47 [2] 7b 5c [2] 74 46 [2] 6a 5b [2] 68 5a [2] 73 5c [2] 6f 5b [2] 73 74 }

  condition:
    any of them
}