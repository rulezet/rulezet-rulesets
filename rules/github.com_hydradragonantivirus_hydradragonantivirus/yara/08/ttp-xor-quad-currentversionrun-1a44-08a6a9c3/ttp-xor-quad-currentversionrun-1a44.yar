rule TTP_XOR_QUAD_CurrentVersionRun_1a44 {
  strings:
    $key_1a44 = { 49 2b [2] 6d 25 [2] 46 09 [2] 68 2b [2] 7c 30 [2] 73 2a [2] 6d 37 [2] 6f 36 [2] 74 30 [2] 68 37 [2] 74 18 }

  condition:
    any of them
}