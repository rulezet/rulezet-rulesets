rule TTP_XOR_QUAD_CurrentVersionRun_2f65 {
  strings:
    $key_2f65 = { 7c 0a [2] 58 04 [2] 73 28 [2] 5d 0a [2] 49 11 [2] 46 0b [2] 58 16 [2] 5a 17 [2] 41 11 [2] 5d 16 [2] 41 39 }

  condition:
    any of them
}