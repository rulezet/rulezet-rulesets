rule TTP_XOR_QUAD_CurrentVersionRun_d096 {
  strings:
    $key_d096 = { 83 f9 [2] a7 f7 [2] 8c db [2] a2 f9 [2] b6 e2 [2] b9 f8 [2] a7 e5 [2] a5 e4 [2] be e2 [2] a2 e5 [2] be ca }

  condition:
    any of them
}