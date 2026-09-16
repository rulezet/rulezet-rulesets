rule TTP_XOR_QUAD_CurrentVersionRun_3c55 {
  strings:
    $key_3c55 = { 6f 3a [2] 4b 34 [2] 60 18 [2] 4e 3a [2] 5a 21 [2] 55 3b [2] 4b 26 [2] 49 27 [2] 52 21 [2] 4e 26 [2] 52 09 }

  condition:
    any of them
}