rule TTP_XOR_QUAD_CurrentVersionRun_d713 {
  strings:
    $key_d713 = { 84 7c [2] a0 72 [2] 8b 5e [2] a5 7c [2] b1 67 [2] be 7d [2] a0 60 [2] a2 61 [2] b9 67 [2] a5 60 [2] b9 4f }

  condition:
    any of them
}