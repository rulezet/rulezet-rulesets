rule TTP_XOR_QUAD_CurrentVersionRun_5d05 {
  strings:
    $key_5d05 = { 0e 6a [2] 2a 64 [2] 01 48 [2] 2f 6a [2] 3b 71 [2] 34 6b [2] 2a 76 [2] 28 77 [2] 33 71 [2] 2f 76 [2] 33 59 }

  condition:
    any of them
}