rule TTP_XOR_QUAD_CurrentVersionRun_2844 {
  strings:
    $key_2844 = { 7b 2b [2] 5f 25 [2] 74 09 [2] 5a 2b [2] 4e 30 [2] 41 2a [2] 5f 37 [2] 5d 36 [2] 46 30 [2] 5a 37 [2] 46 18 }

  condition:
    any of them
}