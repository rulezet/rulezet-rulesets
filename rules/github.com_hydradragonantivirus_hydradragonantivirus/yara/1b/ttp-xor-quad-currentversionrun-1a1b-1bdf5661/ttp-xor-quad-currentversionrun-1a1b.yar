rule TTP_XOR_QUAD_CurrentVersionRun_1a1b {
  strings:
    $key_1a1b = { 49 74 [2] 6d 7a [2] 46 56 [2] 68 74 [2] 7c 6f [2] 73 75 [2] 6d 68 [2] 6f 69 [2] 74 6f [2] 68 68 [2] 74 47 }

  condition:
    any of them
}