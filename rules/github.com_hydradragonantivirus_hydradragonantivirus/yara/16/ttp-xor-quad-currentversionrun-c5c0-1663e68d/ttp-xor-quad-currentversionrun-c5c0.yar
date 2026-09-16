rule TTP_XOR_QUAD_CurrentVersionRun_c5c0 {
  strings:
    $key_c5c0 = { 96 af [2] b2 a1 [2] 99 8d [2] b7 af [2] a3 b4 [2] ac ae [2] b2 b3 [2] b0 b2 [2] ab b4 [2] b7 b3 [2] ab 9c }

  condition:
    any of them
}