rule TTP_XOR_QUAD_CurrentVersionRun_1645 {
  strings:
    $key_1645 = { 45 2a [2] 61 24 [2] 4a 08 [2] 64 2a [2] 70 31 [2] 7f 2b [2] 61 36 [2] 63 37 [2] 78 31 [2] 64 36 [2] 78 19 }

  condition:
    any of them
}