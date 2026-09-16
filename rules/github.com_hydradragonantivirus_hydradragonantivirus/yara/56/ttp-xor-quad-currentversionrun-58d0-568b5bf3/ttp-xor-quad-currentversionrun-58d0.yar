rule TTP_XOR_QUAD_CurrentVersionRun_58d0 {
  strings:
    $key_58d0 = { 0b bf [2] 2f b1 [2] 04 9d [2] 2a bf [2] 3e a4 [2] 31 be [2] 2f a3 [2] 2d a2 [2] 36 a4 [2] 2a a3 [2] 36 8c }

  condition:
    any of them
}