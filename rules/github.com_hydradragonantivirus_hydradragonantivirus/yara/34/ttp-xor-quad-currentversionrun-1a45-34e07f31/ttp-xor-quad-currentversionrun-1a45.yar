rule TTP_XOR_QUAD_CurrentVersionRun_1a45 {
  strings:
    $key_1a45 = { 49 2a [2] 6d 24 [2] 46 08 [2] 68 2a [2] 7c 31 [2] 73 2b [2] 6d 36 [2] 6f 37 [2] 74 31 [2] 68 36 [2] 74 19 }

  condition:
    any of them
}