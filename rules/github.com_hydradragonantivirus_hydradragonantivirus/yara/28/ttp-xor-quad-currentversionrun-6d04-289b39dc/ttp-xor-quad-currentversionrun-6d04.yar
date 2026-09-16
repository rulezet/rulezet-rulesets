rule TTP_XOR_QUAD_CurrentVersionRun_6d04 {
  strings:
    $key_6d04 = { 3e 6b [2] 1a 65 [2] 31 49 [2] 1f 6b [2] 0b 70 [2] 04 6a [2] 1a 77 [2] 18 76 [2] 03 70 [2] 1f 77 [2] 03 58 }

  condition:
    any of them
}