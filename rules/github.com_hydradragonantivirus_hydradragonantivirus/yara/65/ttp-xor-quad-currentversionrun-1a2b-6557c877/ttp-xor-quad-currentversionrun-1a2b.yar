rule TTP_XOR_QUAD_CurrentVersionRun_1a2b {
  strings:
    $key_1a2b = { 49 44 [2] 6d 4a [2] 46 66 [2] 68 44 [2] 7c 5f [2] 73 45 [2] 6d 58 [2] 6f 59 [2] 74 5f [2] 68 58 [2] 74 77 }

  condition:
    any of them
}