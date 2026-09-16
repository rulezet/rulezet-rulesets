rule TTP_XOR_QUAD_CurrentVersionRun_1a79 {
  strings:
    $key_1a79 = { 49 16 [2] 6d 18 [2] 46 34 [2] 68 16 [2] 7c 0d [2] 73 17 [2] 6d 0a [2] 6f 0b [2] 74 0d [2] 68 0a [2] 74 25 }

  condition:
    any of them
}