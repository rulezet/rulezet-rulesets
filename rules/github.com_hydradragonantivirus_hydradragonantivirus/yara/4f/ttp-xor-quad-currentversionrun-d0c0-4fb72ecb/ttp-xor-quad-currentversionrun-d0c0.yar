rule TTP_XOR_QUAD_CurrentVersionRun_d0c0 {
  strings:
    $key_d0c0 = { 83 af [2] a7 a1 [2] 8c 8d [2] a2 af [2] b6 b4 [2] b9 ae [2] a7 b3 [2] a5 b2 [2] be b4 [2] a2 b3 [2] be 9c }

  condition:
    any of them
}