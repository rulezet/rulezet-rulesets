rule TTP_XOR_QUAD_CurrentVersionRun_2355 {
  strings:
    $key_2355 = { 70 3a [2] 54 34 [2] 7f 18 [2] 51 3a [2] 45 21 [2] 4a 3b [2] 54 26 [2] 56 27 [2] 4d 21 [2] 51 26 [2] 4d 09 }

  condition:
    any of them
}