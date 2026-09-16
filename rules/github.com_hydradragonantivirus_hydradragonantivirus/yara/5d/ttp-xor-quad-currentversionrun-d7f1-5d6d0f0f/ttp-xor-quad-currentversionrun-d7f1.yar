rule TTP_XOR_QUAD_CurrentVersionRun_d7f1 {
  strings:
    $key_d7f1 = { 84 9e [2] a0 90 [2] 8b bc [2] a5 9e [2] b1 85 [2] be 9f [2] a0 82 [2] a2 83 [2] b9 85 [2] a5 82 [2] b9 ad }

  condition:
    any of them
}