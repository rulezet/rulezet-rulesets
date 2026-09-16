rule TTP_XOR_QUAD_CurrentVersionRun_1d56 {
  strings:
    $key_1d56 = { 4e 39 [2] 6a 37 [2] 41 1b [2] 6f 39 [2] 7b 22 [2] 74 38 [2] 6a 25 [2] 68 24 [2] 73 22 [2] 6f 25 [2] 73 0a }

  condition:
    any of them
}