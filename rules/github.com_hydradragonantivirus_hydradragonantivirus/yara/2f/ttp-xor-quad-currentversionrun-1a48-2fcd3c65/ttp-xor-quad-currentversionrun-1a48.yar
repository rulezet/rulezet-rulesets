rule TTP_XOR_QUAD_CurrentVersionRun_1a48 {
  strings:
    $key_1a48 = { 49 27 [2] 6d 29 [2] 46 05 [2] 68 27 [2] 7c 3c [2] 73 26 [2] 6d 3b [2] 6f 3a [2] 74 3c [2] 68 3b [2] 74 14 }

  condition:
    any of them
}