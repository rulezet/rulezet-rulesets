rule TTP_XOR_QUAD_CurrentVersionRun_d736 {
  strings:
    $key_d736 = { 84 59 [2] a0 57 [2] 8b 7b [2] a5 59 [2] b1 42 [2] be 58 [2] a0 45 [2] a2 44 [2] b9 42 [2] a5 45 [2] b9 6a }

  condition:
    any of them
}