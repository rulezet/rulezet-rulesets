rule TTP_XOR_QUAD_CurrentVersionRun_1d35 {
  strings:
    $key_1d35 = { 4e 5a [2] 6a 54 [2] 41 78 [2] 6f 5a [2] 7b 41 [2] 74 5b [2] 6a 46 [2] 68 47 [2] 73 41 [2] 6f 46 [2] 73 69 }

  condition:
    any of them
}