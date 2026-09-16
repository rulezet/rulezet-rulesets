rule TTP_XOR_QUAD_CurrentVersionRun_e9d0 {
  strings:
    $key_e9d0 = { ba bf [2] 9e b1 [2] b5 9d [2] 9b bf [2] 8f a4 [2] 80 be [2] 9e a3 [2] 9c a2 [2] 87 a4 [2] 9b a3 [2] 87 8c }

  condition:
    any of them
}