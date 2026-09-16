rule TTP_XOR_QUAD_CurrentVersionRun_670b {
  strings:
    $key_670b = { 34 64 [2] 10 6a [2] 3b 46 [2] 15 64 [2] 01 7f [2] 0e 65 [2] 10 78 [2] 12 79 [2] 09 7f [2] 15 78 [2] 09 57 }

  condition:
    any of them
}