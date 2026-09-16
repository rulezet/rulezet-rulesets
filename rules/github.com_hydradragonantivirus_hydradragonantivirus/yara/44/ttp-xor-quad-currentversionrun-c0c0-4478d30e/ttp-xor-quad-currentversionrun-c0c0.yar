rule TTP_XOR_QUAD_CurrentVersionRun_c0c0 {
  strings:
    $key_c0c0 = { 93 af [2] b7 a1 [2] 9c 8d [2] b2 af [2] a6 b4 [2] a9 ae [2] b7 b3 [2] b5 b2 [2] ae b4 [2] b2 b3 [2] ae 9c }

  condition:
    any of them
}