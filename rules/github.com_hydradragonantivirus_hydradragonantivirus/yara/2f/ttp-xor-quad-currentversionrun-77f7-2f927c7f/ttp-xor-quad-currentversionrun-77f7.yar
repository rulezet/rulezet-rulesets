rule TTP_XOR_QUAD_CurrentVersionRun_77f7 {
  strings:
    $key_77f7 = { 24 98 [2] 00 96 [2] 2b ba [2] 05 98 [2] 11 83 [2] 1e 99 [2] 00 84 [2] 02 85 [2] 19 83 [2] 05 84 [2] 19 ab }

  condition:
    any of them
}