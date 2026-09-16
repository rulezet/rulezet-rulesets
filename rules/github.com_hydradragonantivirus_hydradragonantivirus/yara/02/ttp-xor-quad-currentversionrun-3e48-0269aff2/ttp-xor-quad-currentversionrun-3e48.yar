rule TTP_XOR_QUAD_CurrentVersionRun_3e48 {
  strings:
    $key_3e48 = { 6d 27 [2] 49 29 [2] 62 05 [2] 4c 27 [2] 58 3c [2] 57 26 [2] 49 3b [2] 4b 3a [2] 50 3c [2] 4c 3b [2] 50 14 }

  condition:
    any of them
}