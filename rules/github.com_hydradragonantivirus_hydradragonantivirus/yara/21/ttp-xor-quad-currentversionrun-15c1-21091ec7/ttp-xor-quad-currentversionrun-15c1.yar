rule TTP_XOR_QUAD_CurrentVersionRun_15c1 {
  strings:
    $key_15c1 = { 46 ae [2] 62 a0 [2] 49 8c [2] 67 ae [2] 73 b5 [2] 7c af [2] 62 b2 [2] 60 b3 [2] 7b b5 [2] 67 b2 [2] 7b 9d }

  condition:
    any of them
}