rule TTP_XOR_QUAD_CurrentVersionRun_3479 {
  strings:
    $key_3479 = { 67 16 [2] 43 18 [2] 68 34 [2] 46 16 [2] 52 0d [2] 5d 17 [2] 43 0a [2] 41 0b [2] 5a 0d [2] 46 0a [2] 5a 25 }

  condition:
    any of them
}