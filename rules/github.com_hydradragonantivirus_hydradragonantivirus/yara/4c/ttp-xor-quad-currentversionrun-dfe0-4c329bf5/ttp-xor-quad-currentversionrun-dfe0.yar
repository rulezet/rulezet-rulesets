rule TTP_XOR_QUAD_CurrentVersionRun_dfe0 {
  strings:
    $key_dfe0 = { 8c 8f [2] a8 81 [2] 83 ad [2] ad 8f [2] b9 94 [2] b6 8e [2] a8 93 [2] aa 92 [2] b1 94 [2] ad 93 [2] b1 bc }

  condition:
    any of them
}