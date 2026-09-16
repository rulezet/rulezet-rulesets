rule TTP_XOR_QUAD_CurrentVersionRun_0645 {
  strings:
    $key_0645 = { 55 2a [2] 71 24 [2] 5a 08 [2] 74 2a [2] 60 31 [2] 6f 2b [2] 71 36 [2] 73 37 [2] 68 31 [2] 74 36 [2] 68 19 }

  condition:
    any of them
}