rule TTP_XOR_QUAD_CurrentVersionRun_1d34 {
  strings:
    $key_1d34 = { 4e 5b [2] 6a 55 [2] 41 79 [2] 6f 5b [2] 7b 40 [2] 74 5a [2] 6a 47 [2] 68 46 [2] 73 40 [2] 6f 47 [2] 73 68 }

  condition:
    any of them
}