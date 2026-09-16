rule TTP_XOR_QUAD_CurrentVersionRun_670e {
  strings:
    $key_670e = { 34 61 [2] 10 6f [2] 3b 43 [2] 15 61 [2] 01 7a [2] 0e 60 [2] 10 7d [2] 12 7c [2] 09 7a [2] 15 7d [2] 09 52 }

  condition:
    any of them
}