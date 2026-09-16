rule TTP_XOR_QUAD_CurrentVersionRun_1824 {
  strings:
    $key_1824 = { 4b 4b [2] 6f 45 [2] 44 69 [2] 6a 4b [2] 7e 50 [2] 71 4a [2] 6f 57 [2] 6d 56 [2] 76 50 [2] 6a 57 [2] 76 78 }

  condition:
    any of them
}