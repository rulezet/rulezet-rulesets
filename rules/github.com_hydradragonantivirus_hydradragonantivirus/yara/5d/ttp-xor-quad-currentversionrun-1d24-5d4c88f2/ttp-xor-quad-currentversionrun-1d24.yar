rule TTP_XOR_QUAD_CurrentVersionRun_1d24 {
  strings:
    $key_1d24 = { 4e 4b [2] 6a 45 [2] 41 69 [2] 6f 4b [2] 7b 50 [2] 74 4a [2] 6a 57 [2] 68 56 [2] 73 50 [2] 6f 57 [2] 73 78 }

  condition:
    any of them
}