rule TTP_XOR_QUAD_CurrentVersionRun_c5ca {
  strings:
    $key_c5ca = { 96 a5 [2] b2 ab [2] 99 87 [2] b7 a5 [2] a3 be [2] ac a4 [2] b2 b9 [2] b0 b8 [2] ab be [2] b7 b9 [2] ab 96 }

  condition:
    any of them
}