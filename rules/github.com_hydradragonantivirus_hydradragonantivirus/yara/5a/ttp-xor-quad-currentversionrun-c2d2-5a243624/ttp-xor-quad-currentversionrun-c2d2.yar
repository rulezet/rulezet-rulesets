rule TTP_XOR_QUAD_CurrentVersionRun_c2d2 {
  strings:
    $key_c2d2 = { 91 bd [2] b5 b3 [2] 9e 9f [2] b0 bd [2] a4 a6 [2] ab bc [2] b5 a1 [2] b7 a0 [2] ac a6 [2] b0 a1 [2] ac 8e }

  condition:
    any of them
}