rule TTP_XOR_QUAD_CurrentVersionRun_5204 {
  strings:
    $key_5204 = { 01 6b [2] 25 65 [2] 0e 49 [2] 20 6b [2] 34 70 [2] 3b 6a [2] 25 77 [2] 27 76 [2] 3c 70 [2] 20 77 [2] 3c 58 }

  condition:
    any of them
}