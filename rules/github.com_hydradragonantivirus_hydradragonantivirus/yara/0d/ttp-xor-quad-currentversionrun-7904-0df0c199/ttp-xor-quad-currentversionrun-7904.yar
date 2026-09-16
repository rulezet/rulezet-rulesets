rule TTP_XOR_QUAD_CurrentVersionRun_7904 {
  strings:
    $key_7904 = { 2a 6b [2] 0e 65 [2] 25 49 [2] 0b 6b [2] 1f 70 [2] 10 6a [2] 0e 77 [2] 0c 76 [2] 17 70 [2] 0b 77 [2] 17 58 }

  condition:
    any of them
}