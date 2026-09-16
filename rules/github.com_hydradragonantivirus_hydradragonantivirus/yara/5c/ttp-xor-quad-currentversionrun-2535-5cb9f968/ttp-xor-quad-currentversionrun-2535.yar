rule TTP_XOR_QUAD_CurrentVersionRun_2535 {
  strings:
    $key_2535 = { 76 5a [2] 52 54 [2] 79 78 [2] 57 5a [2] 43 41 [2] 4c 5b [2] 52 46 [2] 50 47 [2] 4b 41 [2] 57 46 [2] 4b 69 }

  condition:
    any of them
}