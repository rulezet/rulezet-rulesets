rule TTP_XOR_QUAD_CurrentVersionRun_77c1 {
  strings:
    $key_77c1 = { 24 ae [2] 00 a0 [2] 2b 8c [2] 05 ae [2] 11 b5 [2] 1e af [2] 00 b2 [2] 02 b3 [2] 19 b5 [2] 05 b2 [2] 19 9d }

  condition:
    any of them
}