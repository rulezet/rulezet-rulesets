rule TTP_XOR_QUAD_CurrentVersionRun_1865 {
  strings:
    $key_1865 = { 4b 0a [2] 6f 04 [2] 44 28 [2] 6a 0a [2] 7e 11 [2] 71 0b [2] 6f 16 [2] 6d 17 [2] 76 11 [2] 6a 16 [2] 76 39 }

  condition:
    any of them
}