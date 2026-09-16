rule TTP_XOR_QUAD_CurrentVersionRun_3665 {
  strings:
    $key_3665 = { 65 0a [2] 41 04 [2] 6a 28 [2] 44 0a [2] 50 11 [2] 5f 0b [2] 41 16 [2] 43 17 [2] 58 11 [2] 44 16 [2] 58 39 }

  condition:
    any of them
}