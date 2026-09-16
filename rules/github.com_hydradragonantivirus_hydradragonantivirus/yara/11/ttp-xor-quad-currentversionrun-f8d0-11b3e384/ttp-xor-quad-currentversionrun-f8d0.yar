rule TTP_XOR_QUAD_CurrentVersionRun_f8d0 {
  strings:
    $key_f8d0 = { ab bf [2] 8f b1 [2] a4 9d [2] 8a bf [2] 9e a4 [2] 91 be [2] 8f a3 [2] 8d a2 [2] 96 a4 [2] 8a a3 [2] 96 8c }

  condition:
    any of them
}