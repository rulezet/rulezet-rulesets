rule TTP_XOR_QUAD_CurrentVersionRun_2365 {
  strings:
    $key_2365 = { 70 0a [2] 54 04 [2] 7f 28 [2] 51 0a [2] 45 11 [2] 4a 0b [2] 54 16 [2] 56 17 [2] 4d 11 [2] 51 16 [2] 4d 39 }

  condition:
    any of them
}