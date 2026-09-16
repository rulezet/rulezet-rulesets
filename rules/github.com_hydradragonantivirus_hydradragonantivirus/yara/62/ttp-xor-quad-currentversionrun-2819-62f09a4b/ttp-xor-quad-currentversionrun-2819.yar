rule TTP_XOR_QUAD_CurrentVersionRun_2819 {
  strings:
    $key_2819 = { 7b 76 [2] 5f 78 [2] 74 54 [2] 5a 76 [2] 4e 6d [2] 41 77 [2] 5f 6a [2] 5d 6b [2] 46 6d [2] 5a 6a [2] 46 45 }

  condition:
    any of them
}