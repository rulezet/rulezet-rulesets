rule TTP_XOR_QUAD_CurrentVersionRun_2855 {
  strings:
    $key_2855 = { 7b 3a [2] 5f 34 [2] 74 18 [2] 5a 3a [2] 4e 21 [2] 41 3b [2] 5f 26 [2] 5d 27 [2] 46 21 [2] 5a 26 [2] 46 09 }

  condition:
    any of them
}