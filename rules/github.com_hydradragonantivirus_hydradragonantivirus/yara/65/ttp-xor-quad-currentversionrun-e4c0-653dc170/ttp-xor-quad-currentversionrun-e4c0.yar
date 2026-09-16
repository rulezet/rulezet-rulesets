rule TTP_XOR_QUAD_CurrentVersionRun_e4c0 {
  strings:
    $key_e4c0 = { b7 af [2] 93 a1 [2] b8 8d [2] 96 af [2] 82 b4 [2] 8d ae [2] 93 b3 [2] 91 b2 [2] 8a b4 [2] 96 b3 [2] 8a 9c }

  condition:
    any of them
}