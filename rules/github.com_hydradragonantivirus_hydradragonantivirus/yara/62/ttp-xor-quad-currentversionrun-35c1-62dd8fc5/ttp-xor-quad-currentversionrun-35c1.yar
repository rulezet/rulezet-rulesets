rule TTP_XOR_QUAD_CurrentVersionRun_35c1 {
  strings:
    $key_35c1 = { 66 ae [2] 42 a0 [2] 69 8c [2] 47 ae [2] 53 b5 [2] 5c af [2] 42 b2 [2] 40 b3 [2] 5b b5 [2] 47 b2 [2] 5b 9d }

  condition:
    any of them
}