rule TTP_XOR_QUAD_CurrentVersionRun_dffa {
  strings:
    $key_dffa = { 8c 95 [2] a8 9b [2] 83 b7 [2] ad 95 [2] b9 8e [2] b6 94 [2] a8 89 [2] aa 88 [2] b1 8e [2] ad 89 [2] b1 a6 }

  condition:
    any of them
}