rule TTP_XOR_QUAD_CurrentVersionRun_2879 {
  strings:
    $key_2879 = { 7b 16 [2] 5f 18 [2] 74 34 [2] 5a 16 [2] 4e 0d [2] 41 17 [2] 5f 0a [2] 5d 0b [2] 46 0d [2] 5a 0a [2] 46 25 }

  condition:
    any of them
}