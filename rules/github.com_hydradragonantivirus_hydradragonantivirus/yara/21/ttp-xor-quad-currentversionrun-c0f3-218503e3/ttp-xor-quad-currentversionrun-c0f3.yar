rule TTP_XOR_QUAD_CurrentVersionRun_c0f3 {
  strings:
    $key_c0f3 = { 93 9c [2] b7 92 [2] 9c be [2] b2 9c [2] a6 87 [2] a9 9d [2] b7 80 [2] b5 81 [2] ae 87 [2] b2 80 [2] ae af }

  condition:
    any of them
}