rule TTP_XOR_QUAD_CurrentVersionRun_c0ca {
  strings:
    $key_c0ca = { 93 a5 [2] b7 ab [2] 9c 87 [2] b2 a5 [2] a6 be [2] a9 a4 [2] b7 b9 [2] b5 b8 [2] ae be [2] b2 b9 [2] ae 96 }

  condition:
    any of them
}