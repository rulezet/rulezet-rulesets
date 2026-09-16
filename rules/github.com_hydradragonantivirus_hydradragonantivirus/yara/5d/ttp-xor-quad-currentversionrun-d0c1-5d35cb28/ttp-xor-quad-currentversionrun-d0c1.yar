rule TTP_XOR_QUAD_CurrentVersionRun_d0c1 {
  strings:
    $key_d0c1 = { 83 ae [2] a7 a0 [2] 8c 8c [2] a2 ae [2] b6 b5 [2] b9 af [2] a7 b2 [2] a5 b3 [2] be b5 [2] a2 b2 [2] be 9d }

  condition:
    any of them
}