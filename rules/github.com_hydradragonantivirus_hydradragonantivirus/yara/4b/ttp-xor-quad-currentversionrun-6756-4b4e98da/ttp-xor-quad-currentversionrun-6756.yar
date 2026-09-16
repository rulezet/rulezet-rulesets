rule TTP_XOR_QUAD_CurrentVersionRun_6756 {
  strings:
    $key_6756 = { 34 39 [2] 10 37 [2] 3b 1b [2] 15 39 [2] 01 22 [2] 0e 38 [2] 10 25 [2] 12 24 [2] 09 22 [2] 15 25 [2] 09 0a }

  condition:
    any of them
}