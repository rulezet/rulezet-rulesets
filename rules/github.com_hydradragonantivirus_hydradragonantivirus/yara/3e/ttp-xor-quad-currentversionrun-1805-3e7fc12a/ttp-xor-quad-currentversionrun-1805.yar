rule TTP_XOR_QUAD_CurrentVersionRun_1805 {
  strings:
    $key_1805 = { 4b 6a [2] 6f 64 [2] 44 48 [2] 6a 6a [2] 7e 71 [2] 71 6b [2] 6f 76 [2] 6d 77 [2] 76 71 [2] 6a 76 [2] 76 59 }

  condition:
    any of them
}