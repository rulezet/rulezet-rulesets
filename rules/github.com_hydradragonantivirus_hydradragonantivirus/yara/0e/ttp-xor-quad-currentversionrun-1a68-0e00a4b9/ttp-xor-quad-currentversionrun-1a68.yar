rule TTP_XOR_QUAD_CurrentVersionRun_1a68 {
  strings:
    $key_1a68 = { 49 07 [2] 6d 09 [2] 46 25 [2] 68 07 [2] 7c 1c [2] 73 06 [2] 6d 1b [2] 6f 1a [2] 74 1c [2] 68 1b [2] 74 34 }

  condition:
    any of them
}