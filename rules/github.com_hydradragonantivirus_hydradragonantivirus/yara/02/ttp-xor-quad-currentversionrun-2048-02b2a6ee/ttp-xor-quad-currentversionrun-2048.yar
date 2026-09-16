rule TTP_XOR_QUAD_CurrentVersionRun_2048 {
  strings:
    $key_2048 = { 73 27 [2] 57 29 [2] 7c 05 [2] 52 27 [2] 46 3c [2] 49 26 [2] 57 3b [2] 55 3a [2] 4e 3c [2] 52 3b [2] 4e 14 }

  condition:
    any of them
}