rule TTP_XOR_QUAD_CurrentVersionRun_2839 {
  strings:
    $key_2839 = { 7b 56 [2] 5f 58 [2] 74 74 [2] 5a 56 [2] 4e 4d [2] 41 57 [2] 5f 4a [2] 5d 4b [2] 46 4d [2] 5a 4a [2] 46 65 }

  condition:
    any of them
}