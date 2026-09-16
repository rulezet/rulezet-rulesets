rule TTP_XOR_QUAD_CurrentVersionRun_c7c1 {
  strings:
    $key_c7c1 = { 94 ae [2] b0 a0 [2] 9b 8c [2] b5 ae [2] a1 b5 [2] ae af [2] b0 b2 [2] b2 b3 [2] a9 b5 [2] b5 b2 [2] a9 9d }

  condition:
    any of them
}