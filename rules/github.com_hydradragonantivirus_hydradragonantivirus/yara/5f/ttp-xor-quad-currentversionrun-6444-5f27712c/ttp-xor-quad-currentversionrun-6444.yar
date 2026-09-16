rule TTP_XOR_QUAD_CurrentVersionRun_6444 {
  strings:
    $key_6444 = { 37 2b [2] 13 25 [2] 38 09 [2] 16 2b [2] 02 30 [2] 0d 2a [2] 13 37 [2] 11 36 [2] 0a 30 [2] 16 37 [2] 0a 18 }

  condition:
    any of them
}