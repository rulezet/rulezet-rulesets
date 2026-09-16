rule TTP_XOR_QUAD_CurrentVersionRun_c6e0 {
  strings:
    $key_c6e0 = { 95 8f [2] b1 81 [2] 9a ad [2] b4 8f [2] a0 94 [2] af 8e [2] b1 93 [2] b3 92 [2] a8 94 [2] b4 93 [2] a8 bc }

  condition:
    any of them
}