rule TTP_XOR_QUAD_CurrentVersionRun_d787 {
  strings:
    $key_d787 = { 84 e8 [2] a0 e6 [2] 8b ca [2] a5 e8 [2] b1 f3 [2] be e9 [2] a0 f4 [2] a2 f5 [2] b9 f3 [2] a5 f4 [2] b9 db }

  condition:
    any of them
}