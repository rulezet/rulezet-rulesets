rule TTP_XOR_QUAD_CurrentVersionRun_79d0 {
  strings:
    $key_79d0 = { 2a bf [2] 0e b1 [2] 25 9d [2] 0b bf [2] 1f a4 [2] 10 be [2] 0e a3 [2] 0c a2 [2] 17 a4 [2] 0b a3 [2] 17 8c }

  condition:
    any of them
}