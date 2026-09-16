rule TTP_XOR_QUAD_CurrentVersionRun_2444 {
  strings:
    $key_2444 = { 77 2b [2] 53 25 [2] 78 09 [2] 56 2b [2] 42 30 [2] 4d 2a [2] 53 37 [2] 51 36 [2] 4a 30 [2] 56 37 [2] 4a 18 }

  condition:
    any of them
}