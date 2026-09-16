rule TTP_XOR_QUAD_CurrentVersionRun_c3d2 {
  strings:
    $key_c3d2 = { 90 bd [2] b4 b3 [2] 9f 9f [2] b1 bd [2] a5 a6 [2] aa bc [2] b4 a1 [2] b6 a0 [2] ad a6 [2] b1 a1 [2] ad 8e }

  condition:
    any of them
}