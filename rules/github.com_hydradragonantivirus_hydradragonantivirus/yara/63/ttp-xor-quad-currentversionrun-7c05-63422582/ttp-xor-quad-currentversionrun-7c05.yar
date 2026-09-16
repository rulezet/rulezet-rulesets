rule TTP_XOR_QUAD_CurrentVersionRun_7c05 {
  strings:
    $key_7c05 = { 2f 6a [2] 0b 64 [2] 20 48 [2] 0e 6a [2] 1a 71 [2] 15 6b [2] 0b 76 [2] 09 77 [2] 12 71 [2] 0e 76 [2] 12 59 }

  condition:
    any of them
}