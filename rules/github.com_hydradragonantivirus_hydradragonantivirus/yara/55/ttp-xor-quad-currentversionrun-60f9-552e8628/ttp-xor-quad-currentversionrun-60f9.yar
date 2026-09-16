rule TTP_XOR_QUAD_CurrentVersionRun_60f9 {
  strings:
    $key_60f9 = { 33 96 [2] 17 98 [2] 3c b4 [2] 12 96 [2] 06 8d [2] 09 97 [2] 17 8a [2] 15 8b [2] 0e 8d [2] 12 8a [2] 0e a5 }

  condition:
    any of them
}