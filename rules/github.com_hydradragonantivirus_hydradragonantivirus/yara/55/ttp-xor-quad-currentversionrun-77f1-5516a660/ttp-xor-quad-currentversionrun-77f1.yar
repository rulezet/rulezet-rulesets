rule TTP_XOR_QUAD_CurrentVersionRun_77f1 {
  strings:
    $key_77f1 = { 24 9e [2] 00 90 [2] 2b bc [2] 05 9e [2] 11 85 [2] 1e 9f [2] 00 82 [2] 02 83 [2] 19 85 [2] 05 82 [2] 19 ad }

  condition:
    any of them
}