rule TTP_XOR_QUAD_CurrentVersionRun_e8d0 {
  strings:
    $key_e8d0 = { bb bf [2] 9f b1 [2] b4 9d [2] 9a bf [2] 8e a4 [2] 81 be [2] 9f a3 [2] 9d a2 [2] 86 a4 [2] 9a a3 [2] 86 8c }

  condition:
    any of them
}