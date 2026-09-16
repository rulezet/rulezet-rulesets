rule TTP_XOR_QUAD_CurrentVersionRun_2e48 {
  strings:
    $key_2e48 = { 7d 27 [2] 59 29 [2] 72 05 [2] 5c 27 [2] 48 3c [2] 47 26 [2] 59 3b [2] 5b 3a [2] 40 3c [2] 5c 3b [2] 40 14 }

  condition:
    any of them
}