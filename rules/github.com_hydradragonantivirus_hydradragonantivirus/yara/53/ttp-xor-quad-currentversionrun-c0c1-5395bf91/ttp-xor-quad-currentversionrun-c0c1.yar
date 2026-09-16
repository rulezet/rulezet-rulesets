rule TTP_XOR_QUAD_CurrentVersionRun_c0c1 {
  strings:
    $key_c0c1 = { 93 ae [2] b7 a0 [2] 9c 8c [2] b2 ae [2] a6 b5 [2] a9 af [2] b7 b2 [2] b5 b3 [2] ae b5 [2] b2 b2 [2] ae 9d }

  condition:
    any of them
}