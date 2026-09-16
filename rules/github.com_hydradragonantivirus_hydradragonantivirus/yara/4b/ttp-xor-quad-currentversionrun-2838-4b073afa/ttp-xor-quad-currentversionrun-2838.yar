rule TTP_XOR_QUAD_CurrentVersionRun_2838 {
  strings:
    $key_2838 = { 7b 57 [2] 5f 59 [2] 74 75 [2] 5a 57 [2] 4e 4c [2] 41 56 [2] 5f 4b [2] 5d 4a [2] 46 4c [2] 5a 4b [2] 46 64 }

  condition:
    any of them
}