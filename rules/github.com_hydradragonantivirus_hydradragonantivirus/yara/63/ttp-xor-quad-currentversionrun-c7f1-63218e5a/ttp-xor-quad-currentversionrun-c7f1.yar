rule TTP_XOR_QUAD_CurrentVersionRun_c7f1 {
  strings:
    $key_c7f1 = { 94 9e [2] b0 90 [2] 9b bc [2] b5 9e [2] a1 85 [2] ae 9f [2] b0 82 [2] b2 83 [2] a9 85 [2] b5 82 [2] a9 ad }

  condition:
    any of them
}