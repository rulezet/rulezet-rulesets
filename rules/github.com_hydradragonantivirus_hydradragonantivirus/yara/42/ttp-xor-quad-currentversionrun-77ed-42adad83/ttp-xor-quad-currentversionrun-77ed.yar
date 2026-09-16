rule TTP_XOR_QUAD_CurrentVersionRun_77ed {
  strings:
    $key_77ed = { 24 82 [2] 00 8c [2] 2b a0 [2] 05 82 [2] 11 99 [2] 1e 83 [2] 00 9e [2] 02 9f [2] 19 99 [2] 05 9e [2] 19 b1 }

  condition:
    any of them
}