rule TTP_XOR_QUAD_CurrentVersionRun_c4c0 {
  strings:
    $key_c4c0 = { 97 af [2] b3 a1 [2] 98 8d [2] b6 af [2] a2 b4 [2] ad ae [2] b3 b3 [2] b1 b2 [2] aa b4 [2] b6 b3 [2] aa 9c }

  condition:
    any of them
}