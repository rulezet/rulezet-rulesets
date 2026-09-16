rule TTP_XOR_QUAD_CurrentVersionRun_1a17 {
  strings:
    $key_1a17 = { 49 78 [2] 6d 76 [2] 46 5a [2] 68 78 [2] 7c 63 [2] 73 79 [2] 6d 64 [2] 6f 65 [2] 74 63 [2] 68 64 [2] 74 4b }

  condition:
    any of them
}