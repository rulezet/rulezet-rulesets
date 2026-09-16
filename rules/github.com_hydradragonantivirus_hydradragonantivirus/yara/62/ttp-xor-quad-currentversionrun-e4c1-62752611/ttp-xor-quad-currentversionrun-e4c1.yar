rule TTP_XOR_QUAD_CurrentVersionRun_e4c1 {
  strings:
    $key_e4c1 = { b7 ae [2] 93 a0 [2] b8 8c [2] 96 ae [2] 82 b5 [2] 8d af [2] 93 b2 [2] 91 b3 [2] 8a b5 [2] 96 b2 [2] 8a 9d }

  condition:
    any of them
}