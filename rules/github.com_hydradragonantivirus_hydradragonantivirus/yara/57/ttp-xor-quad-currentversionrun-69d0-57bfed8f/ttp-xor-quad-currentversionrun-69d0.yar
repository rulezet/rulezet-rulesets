rule TTP_XOR_QUAD_CurrentVersionRun_69d0 {
  strings:
    $key_69d0 = { 3a bf [2] 1e b1 [2] 35 9d [2] 1b bf [2] 0f a4 [2] 00 be [2] 1e a3 [2] 1c a2 [2] 07 a4 [2] 1b a3 [2] 07 8c }

  condition:
    any of them
}