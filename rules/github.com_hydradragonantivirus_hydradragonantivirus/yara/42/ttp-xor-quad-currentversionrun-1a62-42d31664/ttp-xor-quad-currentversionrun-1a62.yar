rule TTP_XOR_QUAD_CurrentVersionRun_1a62 {
  strings:
    $key_1a62 = { 49 0d [2] 6d 03 [2] 46 2f [2] 68 0d [2] 7c 16 [2] 73 0c [2] 6d 11 [2] 6f 10 [2] 74 16 [2] 68 11 [2] 74 3e }

  condition:
    any of them
}