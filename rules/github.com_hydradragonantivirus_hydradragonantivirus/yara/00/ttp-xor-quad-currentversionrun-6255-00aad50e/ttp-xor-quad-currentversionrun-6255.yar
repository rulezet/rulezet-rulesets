rule TTP_XOR_QUAD_CurrentVersionRun_6255 {
  strings:
    $key_6255 = { 31 3a [2] 15 34 [2] 3e 18 [2] 10 3a [2] 04 21 [2] 0b 3b [2] 15 26 [2] 17 27 [2] 0c 21 [2] 10 26 [2] 0c 09 }

  condition:
    any of them
}