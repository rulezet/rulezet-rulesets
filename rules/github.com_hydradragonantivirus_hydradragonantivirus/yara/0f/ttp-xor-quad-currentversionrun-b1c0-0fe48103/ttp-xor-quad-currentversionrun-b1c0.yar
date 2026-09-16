rule TTP_XOR_QUAD_CurrentVersionRun_b1c0 {
  strings:
    $key_b1c0 = { e2 af [2] c6 a1 [2] ed 8d [2] c3 af [2] d7 b4 [2] d8 ae [2] c6 b3 [2] c4 b2 [2] df b4 [2] c3 b3 [2] df 9c }

  condition:
    any of them
}