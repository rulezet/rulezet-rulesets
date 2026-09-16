rule TTP_XOR_QUAD_CurrentVersionRun_3448 {
  strings:
    $key_3448 = { 67 27 [2] 43 29 [2] 68 05 [2] 46 27 [2] 52 3c [2] 5d 26 [2] 43 3b [2] 41 3a [2] 5a 3c [2] 46 3b [2] 5a 14 }

  condition:
    any of them
}