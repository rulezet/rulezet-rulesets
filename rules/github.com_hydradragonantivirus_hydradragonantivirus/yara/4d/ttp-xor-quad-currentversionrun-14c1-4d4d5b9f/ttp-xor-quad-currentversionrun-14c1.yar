rule TTP_XOR_QUAD_CurrentVersionRun_14c1 {
  strings:
    $key_14c1 = { 47 ae [2] 63 a0 [2] 48 8c [2] 66 ae [2] 72 b5 [2] 7d af [2] 63 b2 [2] 61 b3 [2] 7a b5 [2] 66 b2 [2] 7a 9d }

  condition:
    any of them
}