rule TTP_XOR_QUAD_CurrentVersionRun_d1c0 {
  strings:
    $key_d1c0 = { 82 af [2] a6 a1 [2] 8d 8d [2] a3 af [2] b7 b4 [2] b8 ae [2] a6 b3 [2] a4 b2 [2] bf b4 [2] a3 b3 [2] bf 9c }

  condition:
    any of them
}