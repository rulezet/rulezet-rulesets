rule TTP_XOR_QUAD_CurrentVersionRun_2b54 {
  strings:
    $key_2b54 = { 78 3b [2] 5c 35 [2] 77 19 [2] 59 3b [2] 4d 20 [2] 42 3a [2] 5c 27 [2] 5e 26 [2] 45 20 [2] 59 27 [2] 45 08 }

  condition:
    any of them
}