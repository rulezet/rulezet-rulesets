rule TTP_XOR_QUAD_CurrentVersionRun_75c1 {
  strings:
    $key_75c1 = { 26 ae [2] 02 a0 [2] 29 8c [2] 07 ae [2] 13 b5 [2] 1c af [2] 02 b2 [2] 00 b3 [2] 1b b5 [2] 07 b2 [2] 1b 9d }

  condition:
    any of them
}