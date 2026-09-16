rule TTP_XOR_QUAD_CurrentVersionRun_2828 {
  strings:
    $key_2828 = { 7b 47 [2] 5f 49 [2] 74 65 [2] 5a 47 [2] 4e 5c [2] 41 46 [2] 5f 5b [2] 5d 5a [2] 46 5c [2] 5a 5b [2] 46 74 }

  condition:
    any of them
}