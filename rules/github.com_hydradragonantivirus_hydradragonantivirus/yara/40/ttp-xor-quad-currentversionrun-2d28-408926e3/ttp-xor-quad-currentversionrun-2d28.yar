rule TTP_XOR_QUAD_CurrentVersionRun_2d28 {
  strings:
    $key_2d28 = { 7e 47 [2] 5a 49 [2] 71 65 [2] 5f 47 [2] 4b 5c [2] 44 46 [2] 5a 5b [2] 58 5a [2] 43 5c [2] 5f 5b [2] 43 74 }

  condition:
    any of them
}