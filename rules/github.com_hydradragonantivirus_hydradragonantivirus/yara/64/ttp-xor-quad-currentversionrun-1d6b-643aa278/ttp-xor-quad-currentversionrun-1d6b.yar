rule TTP_XOR_QUAD_CurrentVersionRun_1d6b {
  strings:
    $key_1d6b = { 4e 04 [2] 6a 0a [2] 41 26 [2] 6f 04 [2] 7b 1f [2] 74 05 [2] 6a 18 [2] 68 19 [2] 73 1f [2] 6f 18 [2] 73 37 }

  condition:
    any of them
}