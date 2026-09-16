rule TTP_XOR_QUAD_CurrentVersionRun_e4d2 {
  strings:
    $key_e4d2 = { b7 bd [2] 93 b3 [2] b8 9f [2] 96 bd [2] 82 a6 [2] 8d bc [2] 93 a1 [2] 91 a0 [2] 8a a6 [2] 96 a1 [2] 8a 8e }

  condition:
    any of them
}