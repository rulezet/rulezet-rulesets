rule TTP_XOR_QUAD_CurrentVersionRun_2848 {
  strings:
    $key_2848 = { 7b 27 [2] 5f 29 [2] 74 05 [2] 5a 27 [2] 4e 3c [2] 41 26 [2] 5f 3b [2] 5d 3a [2] 46 3c [2] 5a 3b [2] 46 14 }

  condition:
    any of them
}