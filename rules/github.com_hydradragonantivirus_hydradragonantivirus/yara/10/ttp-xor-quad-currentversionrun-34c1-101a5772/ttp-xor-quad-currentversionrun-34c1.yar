rule TTP_XOR_QUAD_CurrentVersionRun_34c1 {
  strings:
    $key_34c1 = { 67 ae [2] 43 a0 [2] 68 8c [2] 46 ae [2] 52 b5 [2] 5d af [2] 43 b2 [2] 41 b3 [2] 5a b5 [2] 46 b2 [2] 5a 9d }

  condition:
    any of them
}