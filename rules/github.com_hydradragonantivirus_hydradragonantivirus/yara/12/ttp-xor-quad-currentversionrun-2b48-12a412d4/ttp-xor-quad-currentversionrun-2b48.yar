rule TTP_XOR_QUAD_CurrentVersionRun_2b48 {
  strings:
    $key_2b48 = { 78 27 [2] 5c 29 [2] 77 05 [2] 59 27 [2] 4d 3c [2] 42 26 [2] 5c 3b [2] 5e 3a [2] 45 3c [2] 59 3b [2] 45 14 }

  condition:
    any of them
}