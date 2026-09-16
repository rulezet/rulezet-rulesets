rule TTP_XOR_QUAD_CurrentVersionRun_c2ca {
  strings:
    $key_c2ca = { 91 a5 [2] b5 ab [2] 9e 87 [2] b0 a5 [2] a4 be [2] ab a4 [2] b5 b9 [2] b7 b8 [2] ac be [2] b0 b9 [2] ac 96 }

  condition:
    any of them
}