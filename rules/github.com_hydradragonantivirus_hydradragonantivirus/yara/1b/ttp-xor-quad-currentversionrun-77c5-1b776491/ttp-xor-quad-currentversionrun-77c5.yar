rule TTP_XOR_QUAD_CurrentVersionRun_77c5 {
  strings:
    $key_77c5 = { 24 aa [2] 00 a4 [2] 2b 88 [2] 05 aa [2] 11 b1 [2] 1e ab [2] 00 b6 [2] 02 b7 [2] 19 b1 [2] 05 b6 [2] 19 99 }

  condition:
    any of them
}