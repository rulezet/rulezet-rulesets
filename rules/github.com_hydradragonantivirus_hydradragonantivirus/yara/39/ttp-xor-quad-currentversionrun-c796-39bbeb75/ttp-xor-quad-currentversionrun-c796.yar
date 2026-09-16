rule TTP_XOR_QUAD_CurrentVersionRun_c796 {
  strings:
    $key_c796 = { 94 f9 [2] b0 f7 [2] 9b db [2] b5 f9 [2] a1 e2 [2] ae f8 [2] b0 e5 [2] b2 e4 [2] a9 e2 [2] b5 e5 [2] a9 ca }

  condition:
    any of them
}