rule TTP_XOR_QUAD_CurrentVersionRun_2528 {
  strings:
    $key_2528 = { 76 47 [2] 52 49 [2] 79 65 [2] 57 47 [2] 43 5c [2] 4c 46 [2] 52 5b [2] 50 5a [2] 4b 5c [2] 57 5b [2] 4b 74 }

  condition:
    any of them
}