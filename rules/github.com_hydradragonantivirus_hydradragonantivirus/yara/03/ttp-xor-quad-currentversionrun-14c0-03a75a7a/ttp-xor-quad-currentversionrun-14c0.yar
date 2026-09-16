rule TTP_XOR_QUAD_CurrentVersionRun_14c0 {
  strings:
    $key_14c0 = { 47 af [2] 63 a1 [2] 48 8d [2] 66 af [2] 72 b4 [2] 7d ae [2] 63 b3 [2] 61 b2 [2] 7a b4 [2] 66 b3 [2] 7a 9c }

  condition:
    any of them
}