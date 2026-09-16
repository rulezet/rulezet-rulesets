rule TTP_XOR_QUAD_CurrentVersionRun_38d0 {
  strings:
    $key_38d0 = { 6b bf [2] 4f b1 [2] 64 9d [2] 4a bf [2] 5e a4 [2] 51 be [2] 4f a3 [2] 4d a2 [2] 56 a4 [2] 4a a3 [2] 56 8c }

  condition:
    any of them
}