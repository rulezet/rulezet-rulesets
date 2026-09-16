rule TTP_XOR_QUAD_CurrentVersionRun_2b55 {
  strings:
    $key_2b55 = { 78 3a [2] 5c 34 [2] 77 18 [2] 59 3a [2] 4d 21 [2] 42 3b [2] 5c 26 [2] 5e 27 [2] 45 21 [2] 59 26 [2] 45 09 }

  condition:
    any of them
}