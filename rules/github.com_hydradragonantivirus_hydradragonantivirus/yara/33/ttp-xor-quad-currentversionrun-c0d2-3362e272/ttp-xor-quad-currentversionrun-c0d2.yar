rule TTP_XOR_QUAD_CurrentVersionRun_c0d2 {
  strings:
    $key_c0d2 = { 93 bd [2] b7 b3 [2] 9c 9f [2] b2 bd [2] a6 a6 [2] a9 bc [2] b7 a1 [2] b5 a0 [2] ae a6 [2] b2 a1 [2] ae 8e }

  condition:
    any of them
}